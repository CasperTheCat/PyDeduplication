from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import cryptography
import pickle
import os
import sys
from . import Utils

class CHashList():
    def __init__(self):
        self.hashList = []
        self.hasWarnedOwnDirectory = False

        self.storeName = ".!HashList"

        # Load
        if os.path.exists(self.storeName) and os.path.getsize(self.storeName) > 0:

            with open(self.storeName, "rb+") as f:
                self.hashList = pickle.load(f)
                print("Loaded {} References".format(len(self.hashList)))
        else:
            with open(self.storeName, "wb+") as nf:
                pass
        

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


    # Maybe a bit of a memory hog :(
    def _GetLongHash(self, fileObj):
        fileObj.seek(0)
        data = fileObj.read()
        fileObj.seek(0)
        return self._GetHash(data)

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

    def _DoesHashCollide(self, iFileSize, name, hShortHash, hLongHash, silent):
        for sz, shs, lhs, nm in self.hashList:
            if sz == iFileSize:
                if (hShortHash != None and shs == hShortHash) and (hLongHash != None and lhs == hLongHash):
                    if name[0] == nm[0]:
                        if not self.hasWarnedOwnDirectory:
                            print("[{}] File collision on identical path. This directory has likely already been scanned somewhere.".format(Utils.Abbreviate("Error")), file=sys.stderr)
                            self.hasWarnedOwnDirectory = True
                    else:
                        if not silent:
                            print("Checked File ({}) collided with {}".format(name, nm))

                    if(hLongHash != None):
                        print("LongHash Check")

                    return True
        return False

    def _DoesLongHashCollide(self, iFileSize, name, hLongHash, silent):
        return self._DoesHashCollide(iFileSize, name, None, hLongHash, silent)
    
    def _DoesShortHashCollide(self, iFileSize, name, hShortHash, silent):
        return self._DoesHashCollide(iFileSize, name, hShortHash, None, silent)
    
    def IsElementKnown(self, root, name, allowLongHashes=False,  silent=False):
        """
        Check Element against internal file list

        Raises:
            IOError
        """
        # Get file size
        fullPath = os.path.join(root, name[0])
        l_FileSize = os.path.getsize(fullPath)

        with open(fullPath, "rb") as ele:

            # Get 'Short' Hash
            l_shortHash = self._GetShortHash(ele, l_FileSize)

            if not self._DoesShortHashCollide(l_FileSize, name, l_shortHash, silent):
                return False

            if allowLongHashes:
                l_longHash = self._GetLongHash(ele)

                if not self._DoesLongHashCollide(l_FileSize, name, l_longHash, silent):
                    return False

        return True

    def AddElement(self, root, name, silent=True):
        fullPath = os.path.join(root, name[0])
        l_FileSize = os.path.getsize(fullPath)

        with open(fullPath, "rb") as ele:
            l_shortHash = self._GetShortHash(ele, l_FileSize)
            l_longHash = self._GetLongHash(ele)
            self.hashList.append((l_FileSize, l_shortHash, l_longHash, name))

    def Write(self):
        with open(self.storeName, "rb+") as f:
            pickle.dump(self.hashList, f)