import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList

def MoveFileToQuarantine(root, fl, args):
    
    path, ext = fl

    absp = os.path.join(root, path)

    movTarPath = os.path.abspath(os.path.join(os.path.join(root, "../.!Quarantine".encode()), path))
    print(movTarPath)
    lxPath = b'/'.join(movTarPath.split(b"\\")) # Linuxise
    splitPath = lxPath.split(b'/')
    print(splitPath)
    currentPath = b'/'.join(splitPath[0:-1])
    print(currentPath)
    #currentFile = split[-1]

    if not os.path.exists(currentPath):
        os.makedirs(currentPath)

    print("Moving {} to {}".format(absp, movTarPath))
    shutil.move(absp, movTarPath)

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


imageTypes = ['jpg', 'jpeg', 'png']

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Generates File Identities with an option to quarantine duplicates")
    parser.add_argument("--allow-quarantine", action="store_true", help='Enable moving files - Dangerous')
    parser.add_argument("-lh", "--long-hash", action="store_true", help='Prevent full file Hashes being generated')
    parser.add_argument("-r", "--raw", action="store_true", help='Prevent hashing the contents of files; instead hash the container')
    parser.add_argument("--silent", action="store_true", help='Silence output')
    parser.add_argument('-t', '--hashtable', nargs=1, type=str, help='Location of hashtable')
    parser.add_argument("path", metavar="path", type=str)



    args = parser.parse_args()

    if not os.path.exists(args.path):
        raise IOError("Directory \"{}\" does not exist".format(
            args.path
    ))

    #if args.hashtable and not os.path.exists(args.hashtable[0]):
    #    raise IOError("Directory \"{}\" does not exist".format(
    #        args.hashtable
    #))

    if not IsDriveSafe(args.path, "./"):
        raise Exception("Path is a parent of the directory this script is in!")

    pathAsBytes = args.path.encode()

    encodedHashtable = args.hashtable[0].encode() if args.hashtable else None

    hashlist = HashList.CHashList(encodedHashtable)

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
                if not hashlist.IsElementKnown(args.path.encode(), relp, ext, allowLongHashes=args.long_hash, silent=args.silent, useRawHashes=args.raw):
                    #hashlist.AddElement(args.path.encode(), relp, ext, False, False)
                    print("Skipping file: {}".format(relp))
                    pass
                else:
                    #print("Wanting to move {}".format(relp))
                    if args.allow_quarantine:
                        MoveFileToQuarantine(args.path.encode(), (relp, ext), args)  
            except KeyboardInterrupt as kbi:
                raise kbi
            except Exception as e:
                print("Error on file {}. Reason: {}".format(fi, e), file=sys.stderr)
                #raise e
                continue