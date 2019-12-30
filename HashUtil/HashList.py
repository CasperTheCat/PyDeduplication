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
        

    def AddElement(self, sizeBytes, fhash, name):
        self.hashList.append((sizeBytes, fhash, name))

    def CheckElementAtPath(self, name, szBytes):
        for sz, hs, nm in self.hashList:
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

            sz, hs, nm = self.hashList[idx]
            fullPath = os.path.join(path, nm[0])

            if not os.path.exists(fullPath):
                if not silent:
                    print("File {} not found, pruning entry.".format(nm))

                if not dry_run:
                    # We free an index here, so we don't increment idx as it now refers to the old idx+1 anyway
                    del self.hashList[idx]
                    continue
            
            idx += 1

    def CheckElement(self, sizeBytes, fhash, name, silent=False):
        for sz, hs, nm in self.hashList:
            
            # Two types of file
            # Collided hash
            # Collided short hash - NYI

            if sz == sizeBytes:
                if hs == fhash:
                    if name[0] == nm[0]:
                        if not self.hasWarnedOwnDirectory:
                            print("[{}] File collision on identical path. This directory has likely already been scanned somewhere.".format(Utils.Abbreviate("Error")), file=sys.stderr)
                            self.hasWarnedOwnDirectory = True
                    else:
                        if not silent:
                            print("Checked File ({}) collided with {}".format(name, nm))

                    return False

        return True


    def Write(self):
        with open(self.storeName, "rb+") as f:
            pickle.dump(self.hashList, f)