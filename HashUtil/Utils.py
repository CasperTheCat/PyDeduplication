#!/usr/bin/env python3

import sys
import getpass
import shutil
import os

vowels = ['a','e','i','o','u']

def _AbbrWord(x: str) -> str:
    outString = x[0]

    for i in range(1, len(x) - 1):
        if not x[i] in vowels:
            outString += x[i]

    outString += x[-1]

    return outString

def Abbreviate(x: str) -> str:
    abbrwords = [_AbbrWord(xs) for xs in x.split(" ")]
    return ' '.join(abbrwords)
    
def GetPassword():
    if sys.stdin.isatty():
        return getpass.getpass()
    else:
        return sys.stdin.readline().rstrip()
    return 

def Quarantine(root, fl, args, relativeQtLocation):  
    path, ext = fl

    absp = os.path.join(root, path)

    movTarPath = os.path.abspath(os.path.join(os.path.join(root, relativeQtLocation.encode()), path))
    #print(movTarPath)
    lxPath = b'/'.join(movTarPath.split(b"\\")) # Linuxise
    splitPath = lxPath.split(b'/')
    #print(splitPath)
    currentPath = b'/'.join(splitPath[0:-1])
    #print(currentPath)
    #currentFile = split[-1]

    if not os.path.exists(currentPath):
        os.makedirs(currentPath)

    print("[INFO] Moving {} to {}".format(absp, movTarPath))
    shutil.move(absp, movTarPath)

if __name__ == "__main__":
    print(Abbreviate(sys.argv[1]))