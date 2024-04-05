#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import cryptography
import pickle
import os
import sys
import re

import perception
from . import Utils
from . import EncryptionHelpers
from .Extensions import *
import platform # Needed for the platform check

# Perceptual Hashing (and others)
import imagehash
from perception import hashers

# Better Arrays
import numpy

# Imports for Type Matching
from PIL import Image

PIL_supportedImageTypes = [b"bmp", b"gif", b"ico", b"jpeg", b"jpg", b"pcx", b"png", b"ppm", b"tga", b"tiff", b"tif" b"dds", b"psd", b"dcx"]

# Temporarily disabling video types. Video is extremely slow and CPU intensive
PERC_supportedVideoTypes = []#b"mp4", b"mov", b"ts", b"flv", b"mpeg", b"mkv"]

# Declare a version number for easier sorting of multiple versions of the format
# I may occasionally add stuff to the format, so I'd like to avoid breaking it
# The first version of this may break stuff though
HASHLIST_VERSION_NUMBER = 3
GLOBAL_HASH_SIZE = 16
HASH_CLIP = 64
GLOBAL_LOG_THRESHOLD = 0.1

# Default the fs record to 4096 bytes
# Increase it only for ZFS-blocks (While they do vary, 128K is safe, and 16K records will just be fully hashed as a short hash)
DEFAULT_RECORD_SIZE = 4096

# About Versions
# 1 is the defacto for the older format. It's actually unused since the old format doesn't have any numbering
# 2 adds support for perceptual hashing when enabled
# 3 adds capabilities

SUPPORTED_CAPABILITIES = []


class CHashList():
    def __init__(self, path = None, additionalCapabilities = []):
        self.hashList = []
        self.hasWarnedOwnDirectory = False
        self.machineKey = EncryptionHelpers.LoadMachineKeys()
        self.isDirty = False
        self.unserialisedBytes = 0
        self.capabilities = []

        self.perceptualHasher = hashers.PHash(hash_size=GLOBAL_HASH_SIZE, highfreq_factor=128, freq_shift=8)
        #self.perceptualHasher = hashers.WaveletHash(hash_size=GLOBAL_HASH_SIZE)

        self.percVideoHasher = hashers.TMKL2(frames_per_second=0.25)#'keyframes')
        #self.percVideoHasher = hashers.FramewiseHasher(self.perceptualHasher, interframe_threshold=0.2)

        # Gins
        self.ginShortHash = {}
        self.ginLongHash = {}
        self.ginPerceptual = {}
        self.ginTypes = {}

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
                self.capabilities += additionalCapabilities
                
        else:
            self.storeName = ".!HashList"
            # # CREATE
            # with open(self.storeName, "wb+") as nf:
            #     pass

        
            # Populate the capabilities
            self.capabilities = SUPPORTED_CAPABILITIES
            self.capabilities += additionalCapabilities


    def _AddToGin(self, gin, key, value):
        """Silly Helper function to avoid a bit of duplication"""
        if key in gin:
            gin[key].append(value)
        else:
            gin[key] = [value]

    def _GenerateGINs(self):
        # Generate
        print("[INFO] Generate Inverted Indices")

        # NUKE
        self.ginShortHash = {}
        self.ginLongHash = {}
        self.ginPerceptual = {}
        self.ginTypes = {}

        # For all hashes
        for idx in range(len(self.hashList)):
            self._AddToGINs(idx)


    def _AddToGINs(self, value):
        if not len(self.hashList) > value:
            print("[WARN] Index {} exceeds HashLists length".format(value))
            return
        (sz, shs, lhs, nm, ph) = self.hashList[value]

        # Add to Short GIN
        if shs is not None:
            self._AddToGin(self.ginShortHash, shs, value)
        
        if lhs is not None:
            self._AddToGin(self.ginLongHash, lhs, value)

        if ph is not None:
            hashAsString = ph[0][:HASH_CLIP]
            self._AddToGin(self.ginPerceptual, hashAsString, value)

        # Handle types
        if nm[1].lower() in PIL_supportedImageTypes:
            self._AddToGin(self.ginTypes, "Image", value)
        elif nm[1].lower() in PERC_supportedVideoTypes:
            self._AddToGin(self.ginTypes, "Video", value)


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
                    self.capabilities = []
            elif len(temp) == 3:
                vn, caps, self.hashList = temp

                if vn >= 3:
                    self.capabilities = caps

            else:
                # Excuse me?
                raise RuntimeError("Hashlist failed to load. This may be due to an outdated version")
            
            print("[INFO] Loaded {} References {}".format(len(self.hashList), "from checkpoint" if fromCheckpoint else ""))

            self._GenerateGINs()


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

    def Prune(self, path, dry_run=False, minimumLogSeverity=Utils.ELogSeverity.Info, logList=None):
        # Prune the paths
        # While because immediately deleted paths will free an index
        dirty = False

        idx = 0
        while idx < len(self.hashList): 

            sz, shs, lhs, nm, ph = self.hashList[idx]
            fullPath = os.path.join(path, nm[0])

            if not os.path.exists(fullPath):
                self._EnqueueLogToList(minimumLogSeverity, Utils.ELogSeverity.Info, "File {} not found, pruning entry.".format(nm), logList)
                if not dry_run:
                    # We free an index here, so we don't increment idx as it now refers to the old idx+1 anyway
                    del self.hashList[idx]
                    dirty = True
                    continue
            
            idx += 1

        if dirty:
            self._GenerateGINs()
            self.isDirty = True

    def _GetHashProvider(self):
        if EXT_SHA512 in self.capabilities:
            return hashes.SHA512_256()
        return hashes.SHA3_256()

    def _GetHash(self, data):
        digest = hashes.Hash(self._GetHashProvider(), backend=default_backend())

        digest.update(data)

        return digest.finalize()

    def _ChunksOf(self, fileObj):
        while True:
            chunk = fileObj.read(1024 * 1024 * 16)

            if not chunk:
                break
            else:
                yield chunk

    # Using 64MiB of ram, surely people have this much
    def _GetLongHash(self, fileObj):
        digest = hashes.Hash(self._GetHashProvider(), backend=default_backend())

        fileObj.seek(0)
        for chunk in self._ChunksOf(fileObj):
            digest.update(chunk)
        fileObj.seek(0)

        return digest.finalize()

    def _GetEffectiveRecordSize(self):
        if EXT_128KiBShortHashBlock in self.capabilities:
            return 128 * 1024
        return 4 * 1024

    def _AlignBlockOffset(self, blockStart):
        """Attempt to align the block to the record boundaries"""
        RecordSize = self._GetEffectiveRecordSize()
        FileBlockMod = blockStart // RecordSize
        FileBlockMod *= RecordSize

        return FileBlockMod

    def _GetCentredBlockOffset(self, fileSize, blockSize):
        """Get the centred block offset"""
        MidPoint = fileSize // 2
        MidBlockPoint = MidPoint - (blockSize // 2)

        return self._AlignBlockOffset(MidBlockPoint)

    def _GetFinalBlockOffset(self, fileSize, blockSize):
        """Get the final block offset and read amount"""
        AlignedBlockStart = self._AlignBlockOffset(fileSize - blockSize)
        ReadToEndBytes = fileSize - AlignedBlockStart

        return AlignedBlockStart, ReadToEndBytes


    def _GetShortHash(self, fileObj, fileSize):

        fileObj.seek(0)

        localBlockSize = self._GetShortHashBlockSize()

        if EXT_IncludeFileMiddleInShortHash in self.capabilities:
            # Check that we can read three blocks
            if fileSize <= localBlockSize * 3:
                # Just read the entire file and reset seek
                return self._GetLongHash(fileObj)
            
            ## This should always be aligned: it's starting from 0
            FirstBlock = fileObj.read(localBlockSize)

            # Compute middle offset and align it
            MidBlockPoint = self._GetCentredBlockOffset(fileSize, localBlockSize)
            fileObj.seek(MidBlockPoint, 0)
            MidBlock = fileObj.read(localBlockSize)

            # Final Block. Align to block, then read extra if required
            FinalBlockOffset, FinalRead = self._GetFinalBlockOffset(fileSize, localBlockSize)
            #print("Reading from {} by {} (FS: {})".format(FinalBlockOffset, FinalRead, fileSize))
            fileObj.seek(FinalBlockOffset, 0)
            LastBlock = fileObj.read(FinalRead)

            sHash = self._GetHash(FirstBlock + MidBlock + LastBlock)

            # Reset seek
            fileObj.seek(0)

            return sHash
        else:
            # Check that we can read two blocks
            if fileSize <= localBlockSize * 2:
                # Just read the entire file and reset seek
                return self._GetLongHash(fileObj)

            firstBlock = fileObj.read(localBlockSize)

            # Final Block. Align to block, then read extra if required
            FinalBlockOffset, FinalRead = self._GetFinalBlockOffset(fileSize, localBlockSize)
            fileObj.seek(FinalBlockOffset, 0)
            LastBlock = fileObj.read(FinalRead)

            sHash = self._GetHash(firstBlock + LastBlock)

            # Reset seek
            fileObj.seek(0) 

            return sHash

    def _PILHash(self, fileObj, limit=None):
        img = Image.open(fileObj)
        imgData = numpy.array(img)
        return self._GetHash(imgData[0:limit])

    def _PerceptualHash(self, fileObj, fileSize, path, fileExtension, useRaw, fullFilePath = None):
        """Implements a perceptual hash"""

        try:
            if fileExtension.lower() in PIL_supportedImageTypes:
                # Hash
                img = Image.open(fileObj)
                #perceptual = imagehash.phash(img, hash_size=GLOBAL_HASH_SIZE, highfreq_factor=256)
                
                perceptual = self.perceptualHasher.compute(img)#, "hex")

                # Yes, return as type!
                return (perceptual, img.width, img.height)
            elif fileExtension.lower() in PERC_supportedVideoTypes and fullFilePath is not None:
                tempFP = fullFilePath.decode()
                perceptual = self.percVideoHasher.compute(tempFP, max_size=120, max_duration=60)
                return (perceptual, 0, 0)
        except Exception as _:
            print("[WARN] Possible Bad File: {} ({})".format(path, _))
        except KeyboardInterrupt as kbi:
            raise kbi

        # Fallback for this is a none type
        # Binary or text files, for example, don't use hash type
        # And make little sense to return anything else
        return None

    def _GetShortHashBlockSize(self):
        if EXT_16MiBShortHashBlock in self.capabilities:
            return 16 * 1024 * 1024

        if EXT_1MiBShortHashBlock in self.capabilities:
            return 1024 * 1024

        if EXT_128KiBShortHashBlock in self.capabilities:
            return 128 * 1024

        return 4 * 1024

    def _ShortHashSelector(self, fileObj, fileSize, path, fileExtension, useRaw):
        if useRaw:
            return self._GetShortHash(fileObj, fileSize)

        # Use Selector
        try:
            if fileExtension.lower() in PIL_supportedImageTypes:
                return self._PILHash(fileObj, self._GetShortHashBlockSize())
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


    def _PerceptualHashScore(self, hPerceptualHash, ph, name, nm, delta, minimumLogSeverity, logList):

        # Return early. It's literally the same file
        if self._SanitisePath(name[0]) == nm[0]:
            return False

        score = -1
        if hPerceptualHash[1] > ph[1]:
            score += 1
        if hPerceptualHash[2] > ph[2]:
            score += 1

        if score > 0:
            self._EnqueueLogToList(minimumLogSeverity, Utils.ELogSeverity.Info, "[COLLISION][PH][LARGER] File {} ({}x{}) collided with {} ({}x{}) at {:02%}".format(self._SanitisePath(name[0]), hPerceptualHash[1], hPerceptualHash[2], nm[0], ph[1], ph[2], 1 - numpy.max(delta) ), logList)
            # We're just bigger!

            #if not silent:
            #    print("[WARN][PH] Found larger image ({}) than original ({}): pruning list.".format(name[0], nm[0]), file=sys.stderr)

            # Prune the ph entry
            #del self.hashList[idx]
            #self._GenerateGINs()
        elif score == 0:
            self._EnqueueLogToList(minimumLogSeverity, Utils.ELogSeverity.Info, "[COLLISION][PH][CROPPED] File {} ({}x{}) collided with {} ({}x{}) at {:02%}".format(self._SanitisePath(name[0]), hPerceptualHash[1], hPerceptualHash[2], nm[0], ph[1], ph[2], 1 - numpy.max(delta) ), logList)
            # Cropped?
            # Warn and ret
            #if not silent:
            #    print("[WARN][PH] Found potentially cropped image ({}): allowing both.".format(name), file=sys.stderr)

        else:
            self._EnqueueLogToList(minimumLogSeverity, Utils.ELogSeverity.Info, "[COLLISION][PH][SMALLER] File {} ({}x{}) collided with {} ({}x{}) at {:02%}".format(self._SanitisePath(name[0]), hPerceptualHash[1], hPerceptualHash[2], nm[0], ph[1], ph[2], 1 - numpy.max(delta) ), logList)

        return False

    # Refactor later!
    # We want to filter info about hard or soft collisions upwards (IE, we want information about *why* a collision occured)
    def _DoesHashCollide(self, iFileSize, name, hShortHash, hLongHash, minimumLogSeverity, logList, hPerceptualHash=None):
        # Check here. Python can be slow with string cmps
        usingPerceptualHash = EXT_PerceptualHash in self.capabilities and not hPerceptualHash is None

        # Lookup the indices directly
        mode = "None"

        indices = []
        if usingPerceptualHash:
            temp = hPerceptualHash[0][:HASH_CLIP]
            if temp in self.ginPerceptual:
                indices = self.ginPerceptual[temp]
                mode = "Perc"
        elif hLongHash is not None:
            if hLongHash in self.ginLongHash:
                indices = self.ginLongHash[hLongHash]
                mode = "Long"
        elif hShortHash is not None:
            if hShortHash in self.ginShortHash:
                indices = self.ginShortHash[hShortHash]
                mode = "Short"

        if len(indices) > 0:
            #print("[INFO] FAST PATH: {}".format(mode))
            for idx in indices:
                # Check Collision Mode
                sz, shs, lhs, nm, ph = self.hashList[idx]

                if sz == iFileSize and ((hShortHash != None and shs == hShortHash) or (hLongHash != None and lhs == hLongHash)):
                    ## Error Printing
                    if self._SanitisePath(name[0]) == nm[0]:
                        if not self.hasWarnedOwnDirectory:
                            self._EnqueueLogToList(minimumLogSeverity, Utils.ELogSeverity.Warn, "File collision on identical path. This directory has likely already been scanned somewhere.", logList)
                            self.hasWarnedOwnDirectory = True
                    else:
                        self._EnqueueLogToList(minimumLogSeverity, Utils.ELogSeverity.Info, "[COLLISION] File {} collided with {}".format(self._SanitisePath(name[0]), nm[0]), logList)

                    return True

                elif usingPerceptualHash:
                    if ph[0] == hPerceptualHash[0]:
                        # TODO: Interim for V2
                        # If a hash collides, but we are larger: don't return the collision
                        # Instead. Warn and bin the old entry

                        return self._PerceptualHashScore(hPerceptualHash, ph, name, nm, [0], minimumLogSeverity, logList)

                        score = -1
                        if hPerceptualHash[1] > ph[1]:
                            score += 1
                        if hPerceptualHash[2] > ph[2]:
                            score += 1

                        if score > 0:
                            # We're just bigger!

                            if not silent:
                                print("[WARN][PH] Found larger image ({}) than original ({}): pruning list.".format(name[0], nm[0]), file=sys.stderr)

                            # Prune the ph entry
                            #del self.hashList[idx]
                            #self._GenerateGINs()
                            return False
                        elif score == 0:
                            # Cropped?
                            # Warn and ret
                            if not silent:
                                print("[WARN][PH] Found potentially cropped image ({}): allowing both.".format(name), file=sys.stderr)
                            return False
                        else:
                            if not silent:
                                print("[COLLISION][PH] File {} ({}x{}) collided with {} ({}x{})".format(self._SanitisePath(name[0]), hPerceptualHash[1], hPerceptualHash[2], nm[0], ph[1], ph[2] ) )
                            # TEMP
                            return False
                    elif name[1].lower() in PERC_supportedVideoTypes:
                        delta = self.percVideoHasher.compute_distance(ph[0], hPerceptualHash[0])
                        if delta < GLOBAL_LOG_THRESHOLD:
                            return self._PerceptualHashScore(hPerceptualHash, ph, name, nm, delta, minimumLogSeverity, logList)
                            #print("[COLLISION][PH] VMatched {} vs {} at {:02%}".format(name[0], nm[0], 1 - numpy.max(delta)))
                    elif name[1].lower() in PIL_supportedImageTypes:
                        delta = self.perceptualHasher.compute_distance(ph[0], hPerceptualHash[0])
                        if delta < GLOBAL_LOG_THRESHOLD:
                            return self._PerceptualHashScore(hPerceptualHash, ph, name, nm, delta, minimumLogSeverity, logList)
                            #print("[COLLISION][PH] IMatched {} vs {} at {:02%}".format(name[0], nm[0], 1 - numpy.max(delta)))

        else:
            # Fallback to the old method
            if usingPerceptualHash:
                # Use a fallback GIN. We aren't going to go full fallback, that'd be slow
                
                if name[1].lower() in PIL_supportedImageTypes:
                    if "Image" in self.ginTypes:
                        indices = self.ginTypes["Image"]
                        mode = "Image Fallback"
                elif name[1].lower() in PERC_supportedVideoTypes: 
                    if "Video" in self.ginTypes:
                        indices = self.ginTypes["Video"]
                        mode = "Video Fallback"

                if not len(indices) > 0:
                    return False

                #print("[INFO] Fallback: {}".format(mode))
                for idx in indices:
                    (sz, shs, lhs, nm, ph) = self.hashList[idx]
                    # ## Size has to match for a *hard* collision
                    # if sz == iFileSize:
                    #     if (hShortHash != None and shs == hShortHash) or (hLongHash != None and lhs == hLongHash):
                    #         if self._SanitisePath(name[0]) == nm[0]:
                    #             if not silent:
                    #                 if not self.hasWarnedOwnDirectory:
                    #                     print("[{}] File collision on identical path. This directory has likely already been scanned somewhere.".format(Utils.Abbreviate("Warning")), file=sys.stderr)
                    #                     self.hasWarnedOwnDirectory = True
                    #         else:
                    #             if not silent:
                    #                 print("[COLLISION] File {} collided with {}".format(self._SanitisePath(name[0]), nm[0]))

                    #         #if(hLongHash != None):
                    #         #    print("LongHash Check")

                    #         return True
                    
                    # Perceptual Hashes
                    if usingPerceptualHash and not ph is None:
                        # To explain: indices 1 and 2 are width and height respectively, so that sorting can be done later on which of these is larger.
                        # I care about keeping originals, not resized versions that happened to get sorted first on the fs
                        #print("[DEBUG] Distance:", self.perceptualHasher.compute_distance(ph[0],hPerceptualHash[0]))

                        if name[1].lower() in PIL_supportedImageTypes:
                            delta = self.perceptualHasher.compute_distance(ph[0], hPerceptualHash[0])
                        elif name[1].lower() in PERC_supportedVideoTypes:
                            delta = self.percVideoHasher.compute_distance(ph[0], hPerceptualHash[0])

                        if delta < GLOBAL_LOG_THRESHOLD:
                            #print("[COLLISION][PH] File {} ({}x{}) collided with {} ({}x{}) at {:02%}".format(self._SanitisePath(name[0]), hPerceptualHash[1], hPerceptualHash[2], nm[0], ph[1], ph[2], 1 - numpy.max(delta) ) )                            
                            return self._PerceptualHashScore(hPerceptualHash, ph, name, nm, delta, minimumLogSeverity, logList)
                
        return False

    def _LockMutex(self, mutex):
        if mutex is not None:
            mutex.acquire()

    def _UnlockMutex(self, mutex):
        if mutex is not None:
            mutex.release()

    def _DoesLongHashCollide(self, iFileSize, name, hLongHash, minimumLogSeverity, logList=None):
        return self._DoesHashCollide(iFileSize, name, None, hLongHash, minimumLogSeverity, logList)
    
    def _DoesShortHashCollide(self, iFileSize, name, hShortHash, minimumLogSeverity, logList=None):
        return self._DoesHashCollide(iFileSize, name, hShortHash, None, minimumLogSeverity, logList)

    def _DoesPerceptualHashCollide(self, iFileSize, name, hPerceptualHash, minimumLogSeverity, logList=None):
        return self._DoesHashCollide(iFileSize, name, None, None, minimumLogSeverity, logList, hPerceptualHash)

    def PrecomputeShortHash(self, root, relPath, extension, fileSize, useRawHashes=False):
        # Get file size
        fullPath = os.path.join(root, relPath)

        # Is the file empty? It'll collide with every other empty file
        if fileSize == 0:
            return None

        with open(fullPath, "rb") as ele:
            # Get 'Short' Hash
            return self._ShortHashSelector(ele, fileSize, relPath, extension, useRawHashes)

    def PrecomputeLongHash(self, root, relPath, extension, fileSize, useRawHashes=False):
        # Get file size
        fullPath = os.path.join(root, relPath)

        # Is the file empty? It'll collide with every other empty file
        if fileSize == 0:
            return None

        with open(fullPath, "rb") as ele:
            return self._LongHashSelector(ele, fileSize, relPath, extension, useRawHashes)

    def IsElementKnownWithHash(self, root, relPath, extension, allowLongHashes=False, useRawHashes=False, minimumLogSeverity=Utils.ELogSeverity.Info, mutex=None, logList=None):
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
            self._EnqueueLogToList(minimumLogSeverity, Utils.ELogSeverity.Info, "[EMPTY] File {} is empty".format(self._SanitisePath(relPath)), logList)
            return True, None, None, None

        # Define as None here to pass back if available
        l_ShortHash = None
        l_LongHash = None
        l_phash = None

        with open(fullPath, "rb") as ele:

            # Get 'Short' Hash
            l_ShortHash = self._ShortHashSelector(ele, l_FileSize, relPath, extension, useRawHashes)

            # Also silence this call when long hashes are allowed. We don't care if miss the call in that case
            # If they are really different, the deep check will pick it up

            # CRITICAL REGION
            self._LockMutex(mutex)
            HasShortHashCollision = self._DoesShortHashCollide(l_FileSize, (relPath, extension), l_ShortHash, Utils.ELogSeverity.Suppress if allowLongHashes else minimumLogSeverity, logList)
            self._UnlockMutex(mutex)
            # END CRITICAL REGION

            if HasShortHashCollision:
                # Short collided, we want to do a full check if enabled
                if allowLongHashes:
                    l_LongHash = self._LongHashSelector(ele, l_FileSize, relPath, extension, useRawHashes)
                    # CRITICAL REGION
                    self._LockMutex(mutex)
                    HasLongHashCollision = self._DoesLongHashCollide(l_FileSize, (relPath, extension), l_LongHash, minimumLogSeverity, logList)
                    self._UnlockMutex(mutex)
                    # END CRITICAL REGION

                    if HasLongHashCollision:
                        # We definitely know this one, so let's return that
                        return True, l_ShortHash, l_LongHash, l_phash
                else:
                    # Since we can't long hash check, get ready to return that we know the element
                    return True, l_ShortHash, l_LongHash, l_phash

            # If we are here, then we did not match short or long hashes
            if EXT_PerceptualHash in self.capabilities and allowLongHashes:
                # Do the perceptual hash
                l_phash = self._PerceptualHash(ele, l_FileSize, relPath, extension, useRawHashes, fullPath)

                if l_phash is not None:
                    # CRITICAL REGION
                    self._LockMutex(mutex)
                    HasPercHashCollision = self._DoesPerceptualHashCollide(l_FileSize, (relPath, extension), l_phash, minimumLogSeverity, logList)
                    self._UnlockMutex(mutex)
                    # END CRITICAL REGION
                    if HasPercHashCollision:
                        return True, l_ShortHash, l_LongHash, l_phash

        return False, l_ShortHash, l_LongHash, l_phash

    def IsElementKnown(self, root, relPath, extension, allowLongHashes=False, useRawHashes=False, minimumLogSeverity=Utils.ELogSeverity.Info, mutex=None, logList=None):
        """
        Check Element against internal file list

        Raises:
            IOError
        """

        IsKnown, _, _, _ = self.IsElementKnownWithHash(root, relPath, extension, allowLongHashes, useRawHashes, minimumLogSeverity, mutex, logList)

        return IsKnown

    def AddHashedElement(self, relativePath, extension, fileSize, shortHash, longHash, perceptualHash ):
        self.hashList.append((fileSize, shortHash, longHash, (relativePath, extension), perceptualHash))
        self._AddToGINs(len(self.hashList) - 1)
        self.isDirty = True

    def AddElement(self, root, relPath, extension, useLongHash=True, useRawHashes=False, disableCheckpoint=False, PrecomputedShortHash=None, PrecomputedLongHash=None, PrecomputedPerceptualHash=None, mutex=None):
        """
            Root = Base Directory
            RelPath = Relative offset from Base
            Extension = File extension
            useLongHash = Should the longer hash be generated
        """
        saneRelPath = self._SanitisePath(relPath)

        fullPath = os.path.join(root, relPath)
        l_FileSize = os.path.getsize(fullPath)

        # Pass these into the local vars
        # Long hash will be passed if one was precomputed even if useLongHash is false
        l_ShortHash = PrecomputedShortHash
        l_LongHash = PrecomputedLongHash
        l_PercHash = PrecomputedPerceptualHash

        with open(fullPath, "rb") as ele:
            if l_ShortHash is None:
                l_ShortHash = self._ShortHashSelector(ele, l_FileSize, relPath, extension, useRawHashes)

            if useLongHash and l_LongHash is None:
                l_LongHash = self._LongHashSelector(ele, l_FileSize, relPath, extension, useRawHashes)
                
            if EXT_PerceptualHash in self.capabilities and l_PercHash is None:
                l_PercHash = self._PerceptualHash(ele, l_FileSize, relPath, extension, useRawHashes, fullPath)

            # CRITICAL REGION
            self._LockMutex(mutex)
            # FORMAT: Size, SH, LH, (Rel+Type), PH
            self.hashList.append((l_FileSize, l_ShortHash, l_LongHash, (saneRelPath, extension), l_PercHash))
            self._AddToGINs(len(self.hashList) - 1)
            self.isDirty = True

            # Checkpoint
            self.unserialisedBytes += l_FileSize

            if self.unserialisedBytes > 1024 * 1024 * 1024 and not disableCheckpoint:
                print("[CHECKPOINT] Saving Checkpoint")
                self.Write(self.storeName + b".tmp", True)
                self.unserialisedBytes = 0

            self._UnlockMutex(mutex)
            # END CRITICAL REGION

        # # Do not bother with this during 
        # # CRITICAL REGION
        # self._LockMutex(mutex)

        # # Checkpoint
        # self.unserialisedBytes += l_FileSize

        # if self.unserialisedBytes > 1024 * 1024 * 1024 and not disableCheckpoint:
        #     print("[CHECKPOINT] Saving Checkpoint")
        #     self.Write(self.storeName + b".tmp", True)
        #     self.unserialisedBytes = 0

        # self._UnlockMutex(mutex)
        # # END CRITICAL REGION

    def Write(self, path=None, overwrite=False):
        if not self.isDirty:
            # No point doing work when nothing was done
            return

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

        self.isDirty = False

    def _EnqueueLogToList(self, MinLogSeverity, LogSeverity, LogLine, LogList):
        if LogSeverity.value < MinLogSeverity.value:
            return

        # We need to enqueue
        if LogList is None:
            print(Utils.FormatLog(LogSeverity, LogLine)[1])
        else:
            LogList.append(Utils.FormatLog(LogSeverity, LogLine))
