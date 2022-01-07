#!/usr/bin/env python3

import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList
from HashUtil import EncryptionHelpers
from HashUtil import Utils
  
def test_pass():
    return

# def test_LoadExisting():
#     # File to Load
#     mTable = HashList.CHashList("Tests/Resources/TestTable.ht".encode())

#     print("DEBUG: ", mTable.capabilities)
    
#     assert("EXT_PerceptualHash" in mTable.capabilities)
#     assert(len(mTable.hashList) == 3)

#     for i in mTable.hashList:
#         print(i)
        
#     # Used for printing :P
#     assert(1==1)


# def test_LoadExistingPHTable():
#         # File to Load
#     mTable = HashList.CHashList("Tests/Resources/TestPerceptualTable.ht".encode())

#     print("DEBUG: ", mTable.capabilities)
    
#     assert("EXT_PerceptualHash" in mTable.capabilities)
#     assert(len(mTable.hashList) == 3)

#     # They should collide. We force the table to have both
#     assert(mTable.hashList[1][4] is not None and mTable.hashList[1][4][0] == mTable.hashList[2][4][0]) 

    