#!/usr/bin/env python3

import sys
import os
import numpy
import argparse
from HashUtil import HashList

def CompareTables(masterTable, comparisonTable):
    print("Comparing {} to {}".format(comparisonTable, masterTable))

    mTable = HashList.CHashList(masterTable.encode())
    cTable = HashList.CHashList(comparisonTable.encode())

    for sz, shs, lhs, nm in cTable.hashList:
        # Check if cElement's hash is known by mTable
        if not mTable._DoesShortHashCollide(sz, nm, shs, True):
            if not mTable._DoesLongHashCollide(sz, nm, lhs, False):
                print("[ONLY][{}] {}".format(comparisonTable, nm[0]))
    

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Generates File Identities with an option to quarantine duplicates")
    parser.add_argument("pathOne", metavar="pathOne", type=str)
    parser.add_argument("pathTwo", metavar="pathTwo", type=str)
    args = parser.parse_args()

    if not os.path.exists(args.pathOne):
        raise IOError("First Path is invalid")
    
    if not os.path.exists(args.pathTwo):
        raise IOError("Second Path is invalid")

    CompareTables(args.pathOne, args.pathTwo)
    CompareTables(args.pathTwo, args.pathOne)

    