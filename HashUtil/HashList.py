#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import cryptography
import pickle
import os
import sys
from . import Utils
from . import EncryptionHelpers
import platform # Needed for the platform check

# Perceptual Hashing (and others)
import imagehash

# Better Arrays
import numpy

# Imports for Type Matching
from PIL import Image

PIL_supportedImageTypes = [b"bmp", b"gif", b"ico", b"jpeg", b"jpg", b"pcx", b"png", b"ppm", b"tga", b"tiff", b"tif" b"dds", b"psd", b"dcx"]

# Declare a version number for easier sorting of multiple versions of the format
# I may occasionally add stuff to the format, so I'd like to avoid breaking it
# The first version of this may break stuff though
HASHLIST_VERSION_NUMBER = 3
GLOBAL_HASH_SIZE = 64

# About Versions
# 1 is the defacto for the older format. It's actually unused since the old format doesn't have any numbering
# 2 adds support for perceptual hashing when enabled

SUPPORTED_CAPABILITIES = ["EXT_PerceptualHash"]


class CHashList():
    def __init__(self, path = None):
        self.hashList = []
        self.hasWarnedOwnDirectory = False
        self.machineKey = EncryptionHelpers.LoadMachineKeys()
        self.unserialisedBytes = 0
        self.capabilities = []

        #LoadHashes
        if path:
            if os.path.isdir(path):
                raise ValueError("Path is a directory, not a file")

            self.storeName = path

            bMasterFileIsValid = os.path.exists(self.storeName) and os.path.getsize(self.storeName) > 0
            bTempFileIsValid = os.path.exists(self.storeName + b".tmp") and os.path.getsize(self.storeName + b".tmp") > 0 

            # If the master file exists and is older, use it
            # If the temp file exists and is older, use it
            # If the master does not exist, load the temp if it exists
            # If the temp does not exist, load the master if it exists

            if bTempFileIsValid and bMasterFileIsValid:
                # Compare the ages and use the most recent
                ordTempModTime = os.path.getmtime(self.storeName + b".tmp")
                ordMasterModTime = os.path.getmtime(self.storeName)

                if ordTempModTime > ordMasterModTime:
                    self._LoadHashList(self.storeName + b".tmp", True)
                else:
                    self._LoadHashList(self.storeName)
            elif bTempFileIsValid:
                self._LoadHashList(self.storeName + b".tmp", True)
            elif bMasterFileIsValid:
                self._LoadHashList(self.storeName)
            else:
                # CREATE
                with open(self.storeName, "wb+") as nf:
                    pass

                # Populate the capabilities
                self.capabilities = SUPPORTED_CAPABILITIES
                
        else:
            self.storeName = ".!HashList"
            # CREATE
            with open(self.storeName, "wb+") as nf:
                pass

        
            # Populate the capabilities
            self.capabilities = SUPPORTED_CAPABILITIES


        
    def _LoadHashList(self, path, fromCheckpoint:bool=False):
        with open(path, "rb+") as f:
            pickled = EncryptionHelpers.Decrypt(f.read(), self.machineKey)
            
            # Handle having an older file version
            temp = pickle.loads(pickled)
            if len(temp) == 1:
                # Old version, skip doing versioning things entirely
                # We also definitely have no extended behaviour
                self.hashList = pickle.loads(pickled)
            elif len(temp) == 2:
                vn, self.hashList = temp

                # Handle versioning
                if vn > 1:
                    self.capabilities.append("EXT_PerceptualHash")
            elif len(temp) == 3:
                vn, caps, self.hashList = temp

                if vn >= 3:
                    self.capabilities = caps

            else:
                # Excuse me?
                raise RuntimeError("Hashlist failed to load. This may be due to an outdated version")
            
            print("Loaded {} References {}".format(len(self.hashList), "from checkpoint" if fromCheckpoint else ""))


    def _SanitisePath(self, path):
        if platform.system() == "Windows":
            return (b'/'.join(path.split(b"\\")))
        else:
            return path

    # def AddElement(self, sizeBytes, fhash, name):
    #     self.hashList.append((sizeBytes, fhash, name))

    def CheckElementAtPath(self, name, szBytes):
        for sz, shs, lhs, nm, ph in self.hashList:
            if name[0] == nm[0]:
                if sz == szBytes:
                    return True
                else:
                    print("Found file, but it's size has changed!")
                    break
        return False

    def Prune(self, path, dry_run=False, silent=True):
        # Prune the paths
        # While because immediately deleted paths will free an index

        idx = 0
        while idx < len(self.hashList): 

            sz, shs, lhs, nm, ph = self.hashList[idx]
            fullPath = os.path.join(path, nm[0])

            if not os.path.exists(fullPath):
                if not silent:
                    print("File {} not found, pruning entry.".format(nm))

                if not dry_run:
                    # We free an index here, so we don't increment idx as it now refers to the old idx+1 anyway
                    del self.hashList[idx]
                    continue
            
            idx += 1

    def _GetHash(self, data):
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())

        digest.update(data)

        return digest.finalize()

    def _ChunksOf(self, fileObj):
        while True:
            chunk = fileObj.read(1024 * 1024 * 64)

            if not chunk:
                break
            else:
                yield chunk

    # Using 64MiB of ram, surely people have this much
    def _GetLongHash(self, fileObj):
        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())

        fileObj.seek(0)
        for chunk in self._ChunksOf(fileObj):
            digest.update(chunk)
        fileObj.seek(0)

        return digest.finalize()

    def _GetShortHash(self, fileObj, fileSize):

        fileObj.seek(0)

        # Check that we can read two blocks
        if fileSize <= 8192:
            # Just read the entire file and reset seek
            return self._GetLongHash(fileObj)

        # assuming 4k block size
        firstBlock = fileObj.read(4096)

        # Seek end
        fileObj.seek(-4096, 2)

        lastBlock = fileObj.read(4096)

        sHash = self._GetHash(firstBlock + lastBlock)

        # Reset seek
        fileObj.seek(0) 

        return sHash

    def _PILHash(self, fileObj, limit=None):
        img = Image.open(fileObj)
        imgData = numpy.array(img)
        return self._GetHash(imgData[0:limit])

    def _PerceptualHash(self, fileObj, fileSize, path, fileExtension, useRaw):
        """Implements a perceptual hash"""
        if useRaw:
            return None

        try:
            if fileExtension.lower() in PIL_supportedImageTypes:
                # Hash
                img = Image.open(fileObj)
                perceptual = imagehash.phash(img, hash_size=GLOBAL_HASH_SIZE)

                # Yes, return as type!
                return (perceptual, img.width, img.height)
        except Exception as _:
            print("[WARN] Possible Bad File: {}".format(path))
        except KeyboardInterrupt as kbi:
            raise kbi

        # Fallback for this is a none type
        # Binary or text files, for example, don't use hash type
        # And make little sense to return anything else
        return None



    def _ShortHashSelector(self, fileObj, fileSize, path, fileExtension, useRaw):
        if useRaw:
            return self._GetShortHash(fileObj, fileSize)

        # Use Selector
        try:
            if fileExtension.lower() in PIL_supportedImageTypes:
                return self._PILHash(fileObj, 4096)
        except Exception as _:
            print("[WARN] Possible Bad File: {}".format(path))
        except KeyboardInterrupt as kbi:
            raise kbi

        return self._GetShortHash(fileObj, fileSize)

    def _LongHashSelector(self, fileObj, fileSize, path, fileExtension, useRaw):
        if useRaw:
            return self._GetLongHash(fileObj)

        try:
            if fileExtension.lower() in PIL_supportedImageTypes:
                return self._PILHash(fileObj)
        except Exception as _:
            print("[WARN] Possible Bad File: {}".format(path))
        except KeyboardInterrupt as kbi:
            raise kbi

        return self._GetLongHash(fileObj)


    # Refactor later!
    # We want to filter info about hard or soft collisions upwards (IE, we want information about *why* a collision occured)
    def _DoesHashCollide(self, iFileSize, name, hShortHash, hLongHash, silent, hPerceptualHash=None):
        # Check here. Python can be slow with string cmps
        usingPerceptualHash = "EXT_PerceptualHash" in self.capabilities and not hPerceptualHash is None


        for idx, (sz, shs, lhs, nm, ph) in enumerate(self.hashList):
            ## Size has to match for a *hard* collision
            if sz == iFileSize:
                if (hShortHash != None and shs == hShortHash) or (hLongHash != None and lhs == hLongHash):
                    if self._SanitisePath(name[0]) == nm[0]:
                        if not silent:
                            if not self.hasWarnedOwnDirectory:
                                print("[{}] File collision on identical path. This directory has likely already been scanned somewhere.".format(Utils.Abbreviate("Warning")), file=sys.stderr)
                                self.hasWarnedOwnDirectory = True
                    else:
                        if not silent:
                            print("[COLLISION] File {} collided with {}".format(self._SanitisePath(name[0]), nm[0]))

                    #if(hLongHash != None):
                    #    print("LongHash Check")

                    return True
            


            # Perceptual Hashes
            if usingPerceptualHash and not ph is None:
                # To explain: indices 1 and 2 are width and height respectively, so that sorting can be done later on which of these is larger.
                # I care about keeping originals, not resized versions that happened to get sorted first on the fs
                
                if ph[0] == hPerceptualHash[0]:

                    # TODO: Interim for V2
                    # If a hash collides, but we are larger: don't return the collision
                    # Instead. Warn and bin the old entry

                    score = -1
                    if hPerceptualHash[1] > ph[1]:
                        score += 1
                    if hPerceptualHash[2] > ph[2]:
                        score += 1

                    if score > 0:
                        # We're just bigger!

                        if not silent:
                            print("[{}][PH] Found larger image than original: pruning list.".format(Utils.Abbreviate("Warning")), file=sys.stderr)

                        # Prune the ph entry
                        del self.hashList[idx]
                        return False
                    elif score == 0:
                        # Cropped?
                        # Warn and ret
                        if not silent:
                            print("[{}][PH] Found potentially cropped image: allowing both.".format(Utils.Abbreviate("Warning")), file=sys.stderr)
                        return False
                    
                    if self._SanitisePath(name[0]) == nm[0]:
                        if not silent:
                            if not self.hasWarnedOwnDirectory:
                                print("[{}] File collision on identical path. This directory has likely already been scanned somewhere.".format(Utils.Abbreviate("Warning")), file=sys.stderr)
                                self.hasWarnedOwnDirectory = True
                    else:
                        if not silent:
                            print("[COLLISION][PH] File {} ({}x{}) collided with {} ({}x{})".format(self._SanitisePath(name[0]), hPerceptualHash[1], hPerceptualHash[2], nm[0], ph[1], ph[2] ) )

                    return True
            

        return False

    def _DoesLongHashCollide(self, iFileSize, name, hLongHash, silent):
        return self._DoesHashCollide(iFileSize, name, None, hLongHash, silent)
    
    def _DoesShortHashCollide(self, iFileSize, name, hShortHash, silent):
        return self._DoesHashCollide(iFileSize, name, hShortHash, None, silent)

    def _DoesPerceptualHashCollide(self, iFileSize, name, hPerceptualHash, silent):
        return self._DoesHashCollide(iFileSize, name, None, None, silent, hPerceptualHash)
    
    def IsElementKnown(self, root, relPath, extension, allowLongHashes=False,  silent=False, useRawHashes=False):
        """
        Check Element against internal file list

        Raises:
            IOError
        """
        
        # Get file size
        fullPath = os.path.join(root, relPath)
        l_FileSize = os.path.getsize(fullPath)

        # Is the file empty? It'll collide with every other empty file
        if l_FileSize == 0:
            print("[EMPTY] File {} is empty".format(self._SanitisePath(relPath)))
            return True

        with open(fullPath, "rb") as ele:

            # Check the perceptual hash first if it's supported. Other the others *will* miss
            if "EXT_PerceptualHash" in self.capabilities:
                # Do the perceptual hash
                l_phash = self._PerceptualHash(ele, l_FileSize, relPath, extension, useRawHashes)

                if self._DoesPerceptualHashCollide(l_FileSize, (relPath, extension), l_phash, silent):
                    return True


            # Get 'Short' Hash
            l_shortHash = self._ShortHashSelector(ele, l_FileSize, relPath, extension, useRawHashes)

            # Also silence this call when long hashes are allowed. We don't care if miss the call in that case
            # If they are really different, the deep check will pick it up
            if not self._DoesShortHashCollide(l_FileSize, (relPath, extension), l_shortHash, silent or allowLongHashes):
                return False

            if allowLongHashes:
                l_longHash = self._LongHashSelector(ele, l_FileSize, relPath, extension, useRawHashes)

                if not self._DoesLongHashCollide(l_FileSize, (relPath, extension), l_longHash, silent):
                    return False                

        return True

    def AddElement(self, root, relPath, extension, silent=True, useLongHash=True, useRawHashes=False, disableCheckpoint=False):
        """
            Root = Base Directory
            RelPath = Relative offset from Base
            Extension = File extension

            Silent = Mutes output
            useLongHash = Should the longer hash be generated
        """
        saneRelPath = self._SanitisePath(relPath)

        fullPath = os.path.join(root, relPath)
        l_FileSize = os.path.getsize(fullPath)

        with open(fullPath, "rb") as ele:
            l_shortHash = self._ShortHashSelector(ele, l_FileSize, relPath, extension, useRawHashes)
            l_longHash = None

            if useLongHash:
                l_longHash = self._LongHashSelector(ele, l_FileSize, relPath, extension, useRawHashes)
                
            l_PercHash = None
            if "EXT_PerceptualHash" in self.capabilities:
                l_PercHash = self._PerceptualHash(ele, l_FileSize, relPath, extension, useRawHashes)

            # FORMAT: Size, SH, LH, (Rel+Type), PH
            self.hashList.append((l_FileSize, l_shortHash, l_longHash, (saneRelPath, extension), l_PercHash))

        self.unserialisedBytes += l_FileSize

        if self.unserialisedBytes > 256 * 1024 * 1024 and not disableCheckpoint:
            print("[CHECKPOINT] Saving Checkpoint")
            self.Write(self.storeName + b".tmp", True)
            self.unserialisedBytes = 0

    def Write(self, path=None, overwrite=False):
        if path:
            # if not os.path.exists(path):
            #     os.makedirs(path)

            if os.path.isdir(path):
                path = os.path.join(path, ".!HashList")

            if os.path.exists(path) and not overwrite: # Again after the first because we may have made a new file
                with open(path, "rb+") as f:
                    pickled = pickle.dumps((HASHLIST_VERSION_NUMBER, self.capabilities, self.hashList))
                    f.write(EncryptionHelpers.Encrypt(pickled, self.machineKey))
            else:
                with open(path, "wb+") as f:
                    pickled = pickle.dumps((HASHLIST_VERSION_NUMBER, self.capabilities, self.hashList))
                    f.write(EncryptionHelpers.Encrypt(pickled, self.machineKey))
        else:
            if os.path.exists(self.storeName):
                with open(self.storeName, "rb+") as f:
                    pickled = pickle.dumps((HASHLIST_VERSION_NUMBER, self.capabilities, self.hashList))
                    f.write(EncryptionHelpers.Encrypt(pickled, self.machineKey))
            else:
                with open(self.storeName, "wb+") as f:
                    pickled = pickle.dumps((HASHLIST_VERSION_NUMBER, self.capabilities, self.hashList))
                    f.write(EncryptionHelpers.Encrypt(pickled, self.machineKey))