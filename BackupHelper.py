#!/usr/bin/env python3

import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList
from HashUtil import Utils

def MoveFileToQuarantine(root, fl, args):
    Utils.Quarantine(root, fl, args, "../.!Quarantine")
    # path, ext = fl

    # absp = os.path.join(root, path)

    # movTarPath = os.path.abspath(os.path.join(os.path.join(root, "../.!Quarantine".encode()), path))
    # print(movTarPath)
    # lxPath = b'/'.join(movTarPath.split(b"\\")) # Linuxise
    # splitPath = lxPath.split(b'/')
    # print(splitPath)
    # currentPath = b'/'.join(splitPath[0:-1])
    # print(currentPath)
    # #currentFile = split[-1]

    # if not os.path.exists(currentPath):
    #     os.makedirs(currentPath)

    # print("[INFO] Moving {} to {}".format(absp, movTarPath))
    # #shutil.move(absp, movTarPath)

def IsDriveSafe(a,b):
    # Check path isn't our parent
    # I should check this!

    absa = os.path.abspath(a)
    absb = os.path.abspath(b)

    if platform.system() == "Windows":

        drivea = absa.split("\\")[0]
        driveb = absb.split("\\")[0]

        if not drivea == driveb:
            return True

        relp = os.path.relpath(absa, absb)

        relpsl = relp.split("\\")
        if(relpsl[-1] == ".."):
            # Can get to this directory :(
            return False
    else:
        relp = os.path.relpath(absa, absb)

        relpsl = relp.split("/")
        if(relpsl[-1] == ".."):
            # Can get to this directory :(
            return False

    return True

def GetExtension(filename: str):
    return filename.split(".")[-1].lower().encode()

excludeDirs = [".git"]
excludeFileTypes = [b"gitignore"]


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Generates File Identities with an option to quarantine duplicates")
    parser.add_argument("--allow-quarantine", action="store_true", help='Enable moving files - Dangerous')
    parser.add_argument("-lh", "--long-hash", action="store_true", help='Enable full file Hashes being generated')
    parser.add_argument("-r", "--raw", action="store_true", help='Prevent hashing the contents of files; instead hash the container')
    parser.add_argument("--silent", action="store_true", help='Silence output')
    parser.add_argument('-t', '--hashtable', nargs=1, type=str, help='Location of hashtable')
    parser.add_argument("src", metavar="src", type=str)
    parser.add_argument("dst", metavar="dst", type=str)



    args = parser.parse_args()

    if not os.path.exists(args.src):
        raise IOError("Directory \"{}\" does not exist".format(
            args.src
    ))

    if not os.path.exists(args.dst):
        raise IOError("Directory \"{}\" does not exist".format(
            args.dst
    ))

    if not IsDriveSafe(args.src, "./") and args.allow_quarantine:
        raise Exception("Path is a parent of the directory this script is in!")
    
    if not IsDriveSafe(args.dst, "./") and args.allow_quarantine:
        raise Exception("Path is a parent of the directory this script is in!")

    srcAsBytes = args.src.encode()
    dstAsBytes = args.dst.encode()

    encodedHashtable = args.hashtable[0].encode() if args.hashtable else None

    hashlist = HashList.CHashList(encodedHashtable)

    LoggingLevel = minimumLogSeverity=Utils.ELogSeverity.Suppress if args.silent else Utils.ELogSeverity.Info

    for r, d, p in os.walk(args.src):
        d[:] = [x for x in d if x not in excludeDirs]
        p[:] = [x for x in p if GetExtension(x) not in excludeFileTypes]

        if ".skipfolder" in p:
            d[:] = []#[x for x in d]
            Utils.PrintPrettyLog(Utils.ELogSeverity.Verbose, "[IGNORE] Skipping Below {}".format(r))
            continue

        for fi in p:
            # Let's catagorise these
            f = fi.split(".")
            path = os.path.join(r, fi)
            relp = os.path.relpath(path, os.path.abspath(args.src)).encode()
            ext = f[len(f) - 1].lower().encode()

            try:
                if not hashlist.IsElementKnown(args.src.encode(), relp, ext, allowLongHashes=args.long_hash, minimumLogSeverity=LoggingLevel, useRawHashes=args.raw):
                    hashlist.AddElement(args.src.encode(), relp, ext, useLongHash=args.long_hash, useRawHashes=args.raw, disableCheckpoint=True)
                    # if not args.silent:
                    #     Utils.PrintPrettyLog(Utils.ELogSeverity.Info, "[CLEAR] File: {}".format(relp))
                    FullSource = os.path.join(args.src.encode(), relp)
                    FullDestination = os.path.join(dstAsBytes, relp)
                    DestFolder = os.path.dirname(FullDestination)
                    if not os.path.exists(FullDestination):
                        print("Wanting to copy {} to {}. Dest: {}".format(FullSource, FullDestination, os.path.join(dstAsBytes, relp)))
                        if not os.path.exists(DestFolder):
                            os.makedirs(DestFolder)
                        shutil.copy2(FullSource, FullDestination)
                    
                    
                else:
                    pass
                    #if args.allow_quarantine:
                        #CopyFile(args.path.encode(), (relp, ext), args)  
            except KeyboardInterrupt as kbi:
                raise kbi
            except Exception as e:
                Utils.PrintPrettyLog(Utils.ELogSeverity.Error, "Error on file {}. Reason: {}".format(relp, e))
                continue