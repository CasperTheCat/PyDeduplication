#!/usr/bin/env python3

import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList
from HashUtil import Utils
from HashUtil import Extensions

def MoveFileToQuarantine(r, fl, args):
    Utils.Quarantine(r, fl, args, "../.!Quarantine")
    # p, t = fl
    # absp = os.path.join(r.encode(), p.encode())
    # movTarPart = os.path.join(os.path.abspath(os.path.join(args.path.encode(), "../.!Quarantine".encode())), t)
    # movTar = os.path.join(movTarPart, p.encode())

    # if not os.path.exists(movTarPart):
    #     os.makedirs(movTarPart)

    # print("[INFO] Moving {} to {}".format(absp, movTar))
    # shutil.move(absp, movTar)

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

def GetHashExtensions(arguments: argparse.Namespace):
    HashExts = []

    if arguments.large_block:
        print("[EXTENSION] 16MiB Block Enabled")
        HashExts.append(Extensions.EXT_16MiBShortHashBlock)
    elif arguments.medium_block:
        print("[EXTENSION] 1MiB Block Enabled")
        HashExts.append(Extensions.EXT_1MiBShortHashBlock)

    if arguments.perceptual:
        print("[EXTENSION] Perceptual Hashing Enabled")
        HashExts.append(Extensions.EXT_PerceptualHash)

    if arguments.sha512:
        print("[EXTENSION] SHA512 Enabled")
        HashExts.append(Extensions.EXT_SHA512)

    if arguments.centred_short_hash:
        print("[EXTENSION] Centred Short Hash Block Enabled")
        HashExts.append(Extensions.EXT_IncludeFileMiddleInShortHash)

    return HashExts

excludeDirs = [".git"]
excludeFileTypes = [b"gitignore", b"gitmodules"]

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Generates File Identities with an option to quarantine duplicates")
    parser.add_argument("--allow-quarantine", action="store_true", help='Enable moving files - Dangerous')
    parser.add_argument("-f", "--fast", action="store_true", help='Use short hashes for comparison')
    parser.add_argument("-sh", "--short-hash", action="store_true", help='Prevent full file Hashes being generated (Implies -f)')
    parser.add_argument("-r", "--raw", action="store_true", help='Prevent hashing the contents of files; instead hash the container')
    parser.add_argument("--silent", action="store_true", help='Silence output')
    parser.add_argument('-t', '--hashtable', nargs=1, type=str, help='Location of hashtable')
    parser.add_argument('--sha512', action="store_true", help='Use SHA512_256 over SHA3_256')
    parser.add_argument('-p', '--perceptual', action="store_true", help='Use Perceptual Hashing')
    parser.add_argument('-ch', '--centred-short-hash', action="store_true", help='Add a third, infixed hash block for short hash')
    parser.add_argument('-mb', '--medium-block', action="store_true", help='Use 1MiB short hash block size, up from 4Ki')
    parser.add_argument('-lb', '--large-block', action="store_true", help='Use 16MiB short hash block size, up from 4Ki or 1Mi')
    parser.add_argument("path", metavar="path", type=str)

    args = parser.parse_args()

    # Sanity Short and non-raw
    if args.short_hash and not args.raw:
        print("[WARN]: Using short hashes without specifing the raw hash mode may lead to false positive collisions.")

    if args.allow_quarantine and args.short_hash:
        print("[WARN]: Using quarantine without the added safety of full-file hashes is not advised.")
        if not args.raw:
            print("[ERRR]: Quarantining enabled without raw or full-file hashes. This configuration WILL result in quarantining files in error. Either specify raw hashes or renable full-file hashing!")
            sys.exit(-1)

    


    if not os.path.exists(args.path):
        raise IOError("Directory \"{}\" does not exist".format(
            args.path
    ))

    #if args.hashtable and not os.path.exists(args.hashtable[0]):
    #    raise IOError("Directory \"{}\" does not exist".format(
    #        args.hashtable
    #))

    if not IsDriveSafe(args.path, "./") and args.allow_quarantine:
        raise Exception("Path is a parent of the directory this script is in!")

    pathAsBytes = args.path.encode()

    encodedHashtable = args.hashtable[0].encode() if args.hashtable else None

    WantedExtensions = GetHashExtensions(args)

    hashlist = HashList.CHashList(encodedHashtable, WantedExtensions)
    hashlist.Prune(pathAsBytes, dry_run=False, silent=args.silent)

    for r, d, p in os.walk(args.path):
        d[:] = [x for x in d if x not in excludeDirs]
        p[:] = [x for x in p if GetExtension(x) not in excludeFileTypes]

        if ".skipfolder" in p:
            d[:] = []#[x for x in d]
            print("Skipping Below {}".format(r))
            continue

        for fi in p:
            # Let's catagorise these
            f = fi.split(".")
            path = os.path.join(r, fi)
            relp = os.path.relpath(path, os.path.abspath(args.path)).encode()
            ext = f[len(f) - 1].lower().encode()

            try:
                if not hashlist.IsElementKnown(pathAsBytes, relp, ext, allowLongHashes=(not (args.fast and args.short_hash)), silent=args.silent, useRawHashes=args.raw):
                    print("[ADDITION] File: {}".format(relp))
                    hashlist.AddElement(pathAsBytes, relp, ext, silent=args.silent, useLongHash=(not args.short_hash), useRawHashes=args.raw)
                else:
                    if args.allow_quarantine:
                        MoveFileToQuarantine(r, (fi, ext), args)  
            except KeyboardInterrupt as kbi:
                raise kbi
            except Exception as e:
                print("Error on file {}: {}".format(fi, e), file=sys.stderr)
                continue

    hashlist.Write()
