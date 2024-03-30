#!/usr/bin/env python3

import sys
import getpass
import shutil
import os
from enum import Enum

vowels = ['a','e','i','o','u']

class ELogSeverity(Enum):
    Verbose = 1
    Info = 2
    Warn = 3
    Error = 4
    Fatal = 5
    Suppress = 6 # Used to suppress logging

def _AbbrWord(x: str, Cutoff=1, MinLength=4) -> str:
    outString = x[:Cutoff]

    for i in range(Cutoff, len(x) - Cutoff):
        if not x[i] in vowels:
            outString += x[i]

    outString += x[-Cutoff:]

    if len(outString) < MinLength:
        return x

    return outString

def Abbreviate(x: str, Cutoff=1, MinLength=4) -> str:
    abbrwords = [_AbbrWord(xs, Cutoff, MinLength) for xs in x.split(" ")]
    return ' '.join(abbrwords)

def FormatLog(LogSeverity, LogLine):
    RequiresSpace = "[" != str(LogLine)[0]
    return (LogSeverity, "[{}]{}{}".format(Abbreviate(LogSeverity.name).upper(), " " if RequiresSpace else "", LogLine))
    
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

def PrintPrettyLog(Severity, Log):
    _, Line = FormatLog(Severity, Log)
    if Severity == ELogSeverity.Error or Severity == ELogSeverity.Fatal:
        print(Line, file=sys.stderr)
        # Raise
        if Severity == Severity == ELogSeverity.Fatal:
            raise Exception(Line)
    else:
        print(Line)

if __name__ == "__main__":
    print(Abbreviate(sys.argv[1]))

    print(FormatLog(ELogSeverity.Fatal, "Help Debug Me"))