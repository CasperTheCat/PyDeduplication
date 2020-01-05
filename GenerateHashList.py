import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList

hashlist = HashList.CHashList()

def MoveFileToQuarantine(r, fl, args):
    p, t = fl
    absp = os.path.join(r.encode(), p.encode())
    movTarPart = os.path.join(os.path.abspath(os.path.join(args.path.encode(), "../.!Quarantine".encode())), t)
    movTar = os.path.join(movTarPart, p.encode())

    if not os.path.exists(movTarPart):
        os.makedirs(movTarPart)

    print("Moving {} to {}".format(absp, movTar))
    shutil.move(absp, movTar)

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

    return True

    



imageTypes = ['jpg', 'jpeg', 'png']

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Generates File Identities with an option to quarantine duplicates")
    parser.add_argument("--allow-quarantine", action="store_true")
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("path", metavar="path", type=str)

    args = parser.parse_args()

    if not os.path.exists(args.path):
        raise IOError("Directory \"{}\" does not exist".format(
            args.path
    ))

    if not IsDriveSafe(args.path, "./"):
        raise Exception("Path is a parent of the directory this script is in!")

    pathAsBytes = args.path.encode()

    hashlist.Prune(pathAsBytes, dry_run=False, silent=args.silent)

    for r, d, p in os.walk(args.path):
        for fi in p:
            # Let's catagorise these
            f = fi.split(".")
            path = os.path.join(r, fi)
            relp = os.path.relpath(path, os.path.abspath(args.path))
            fl = (relp.encode(), f[len(f) - 1].lower().encode())

            try:
                if not hashlist.IsElementKnown(pathAsBytes, fl, allowLongHashes=args.allow_quarantine, silent=args.silent):
                    print("Adding file: {}".format(fl))
                    hashlist.AddElement(pathAsBytes, fl, silent=args.silent)
                else:
                    if args.allow_quarantine:
                        MoveFileToQuarantine(r, (fi, fl[1]), args)  
            except KeyboardInterrupt as kbi:
                raise kbi
            except Exception as e:
                print("Error on file {}: {}".format(fi, e), file=sys.stderr)
                continue

    hashlist.Write()