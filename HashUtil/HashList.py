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

# Better Arrays
import numpy

# Imports for Type Matching
from PIL import Image

PIL_supportedImageTypes = [b"bmp", b"gif", b"ico", b"jpeg", b"jpg", b"pcx", b"png", b"ppm", b"tga", b"tiff", b"tif" b"dds", b"psd", b"dcx"]


class CHashList():
    def __init__(self, path = None):
        self.hashList = []
        self.hasWarnedOwnDirectory = False
        self.machineKey = EncryptionHelpers.LoadMachineKeys()
        self.unserialisedBytes = 0

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
                with open(self.storeName, "wb+") as nf:
                    pass
        else:
            self.storeName = ".!HashList"
            with open(self.storeName, "wb+") as nf:
                pass


        
    def _LoadHashList(self, path, fromCheckpoint:bool=False):
        with open(path, "rb+") as f:
            pickled = EncryptionHelpers.Decrypt(f.read(), self.machineKey)
            self.hashList = pickle.loads(pickled)
            print("Loaded {} References {}".format(len(self.hashList), "from checkpoint" if fromCheckpoint else ""))


    def _SanitisePath(self, path):
        if platform.system() == "Windows":
            return (b'/'.join(path.split(b"\\")))
        else:
            return path

    # def AddElement(self, sizeBytes, fhash, name):
    #     self.hashList.append((sizeBytes, fhash, name))

    def CheckElementAtPath(self, name, szBytes):
        for sz, shs, lhs, nm in self.hashList:
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

            sz, shs, lhs, nm = self.hashList[idx]
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

    def _ShortHashSelector(self, fileObj, fileSize, path, fileExtension, useRaw):
        if useRaw:
            return self._GetShortHash(fileObj, fileSize)

        # Use Selector
        try:
            if fileExtension.lower() in PIL_supportedImageTypes:
                return self._PILHash(fileObj, 4096)
        except Exception as _:
            print("Possible Bad File: {}".format(path.decode()))
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
            print("Possible Bad File: {}".format(path.decode()))
        except KeyboardInterrupt as kbi:
            raise kbi

        return self._GetLongHash(fileObj)


    def _DoesHashCollide(self, iFileSize, name, hShortHash, hLongHash, silent):
        for sz, shs, lhs, nm in self.hashList:
            if sz == iFileSize:
                if (hShortHash != None and shs == hShortHash) or (hLongHash != None and lhs == hLongHash):
                    if self._SanitisePath(name[0]) == nm[0]:
                        if not silent:
                            if not self.hasWarnedOwnDirectory:
                                print("[{}] File collision on identical path. This directory has likely already been scanned somewhere.".format(Utils.Abbreviate("Warning")), file=sys.stderr)
                                self.hasWarnedOwnDirectory = True
                    else:
                        if not silent:
                            print("[COLLISION] File \"{}\" collided with \"{}\"".format(self._SanitisePath(name[0]).decode(), nm[0].decode()))

                    #if(hLongHash != None):
                    #    print("LongHash Check")

                    return True
        return False

    def _DoesLongHashCollide(self, iFileSize, name, hLongHash, silent):
        return self._DoesHashCollide(iFileSize, name, None, hLongHash, silent)
    
    def _DoesShortHashCollide(self, iFileSize, name, hShortHash, silent):
        return self._DoesHashCollide(iFileSize, name, hShortHash, None, silent)
    
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
            print("[EMPTY] File \"{}\" is empty".format(self._SanitisePath(relPath).decode()))
            return True

        with open(fullPath, "rb") as ele:

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

    def AddElement(self, root, relPath, extension, silent=True, useLongHash=True, useRawHashes=False):
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
                
            self.hashList.append((l_FileSize, l_shortHash, l_longHash, (saneRelPath, extension)))

        self.unserialisedBytes += l_FileSize

        if self.unserialisedBytes > 256 * 1024 * 1024:
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
                    pickled = pickle.dumps(self.hashList)
                    f.write(EncryptionHelpers.Encrypt(pickled, self.machineKey))
            else:
                with open(path, "wb+") as f:
                    pickled = pickle.dumps(self.hashList)
                    f.write(EncryptionHelpers.Encrypt(pickled, self.machineKey))
        else:
            if os.path.exists(self.storeName):
                with open(self.storeName, "rb+") as f:
                    pickled = pickle.dumps(self.hashList)
                    f.write(EncryptionHelpers.Encrypt(pickled, self.machineKey))
            else:
                with open(self.storeName, "wb+") as f:
                    pickled = pickle.dumps(self.hashList)
                    f.write(EncryptionHelpers.Encrypt(pickled, self.machineKey))