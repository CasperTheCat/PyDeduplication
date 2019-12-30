from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import cryptography
import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList

hashlist = HashList.CHashList()

def GetLongHash(root, fl):
    absp = os.path.join(root, fl)

    #digest = hashes.Hash(hashes.SHA512_256(), backend=default_backend())
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())

    with open(absp, "rb+") as fi:
        f = fi.read()
        digest.update(f)
        #for ln in fi.readlines():
        #    digest.update(ln)

    ha = digest.finalize()

    return ha

def MoveFileToQuarantine(r, fl, args):
    p, t = fl
    absp = os.path.join(r,p)
    movTarPart = os.path.join(os.path.abspath(os.path.join(args.path, "../.!Quarantine")), t)
    movTar = os.path.join(movTarPart, p)

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
    parser.add_argument("path", metavar="path", type=str)

    args = parser.parse_args()

    if not os.path.exists(args.path):
        raise IOError("Directory \"{}\" does not exist".format(
            args.path
    ))

    if not IsDriveSafe(args.path, "./"):
        raise Exception("Path is a parent of the directory this script is in!")

    hashlist.Prune(args.path, dry_run=False, silent=False)

    for r, d, p in os.walk(args.path):
        for fi in p:
            # Let's catagorise these
            f = fi.split(".")
            path = os.path.join(r, fi)
            relp = os.path.relpath(path, os.path.abspath(args.path))
            fl = (relp, f[len(f) - 1].lower())

            if hashlist.CheckElementAtPath(fl, os.path.getsize(path)):
                continue
            else:
                print("New File {}".format(relp))

            # Get Size
            szBytes = os.path.getsize(path)

            try:
                fHash = GetLongHash(r, fi)
            except:
                print("Error on file {}".format(fi), file=sys.stderr)
                continue

            if hashlist.CheckElement(szBytes, fHash, fl):
                hashlist.AddElement(szBytes, fHash, fl)
            else:
                if args.allow_quarantine:
                    MoveFileToQuarantine(r, (fi, fl[1]), args)

    #hashlist.Write()