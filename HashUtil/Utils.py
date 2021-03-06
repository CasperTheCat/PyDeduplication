#!/usr/bin/env python3

import sys
import getpass

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

if __name__ == "__main__":
    import sys

    print(Abbreviate(sys.argv[1]))