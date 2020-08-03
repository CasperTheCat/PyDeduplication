import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList
from HashUtil import EncryptionHelpers

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Removes password-based encryption and applies machine keying for this device")
    parser.add_argument("hashtable", metavar="hashtable", type=str)
    parser.add_argument("password", metavar="password", type=str)
    parser.add_argument('-s', '--salt', nargs=1, type=str, help='Salt to use')
    parser.add_argument('-o', '--out', nargs=1, type=str, help='Out Location')

    args = parser.parse_args()

    outputFile = args.out[0] if args.out else args.hashtable


    dat = None

    with open(args.hashtable, "rb+") as f:
        dat = f.read()

    # Recover Salt
    encodedSalt = args.salt[0].encode() if args.salt else dat[:16]

    # Trim Data
    dat = dat[len(encodedSalt):]

    # PBKDF2 Keys
    key = EncryptionHelpers.KeyFromPassword(args.password, encodedSalt)

    # Decrypt
    raw = EncryptionHelpers.Decrypt(dat, key, encodedSalt)

    # Encrypt
    mkenc = EncryptionHelpers.Encrypt(raw, EncryptionHelpers.LoadMachineKeys())

    with open(outputFile, "wb+") as f:
        f.write(mkenc)
