import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList
from HashUtil import EncryptionHelpers

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Removes Machine Keying from a hashtable and applies a password-based encryption for transport")
    parser.add_argument("hashtable", metavar="hashtable", type=str)
    parser.add_argument("password", metavar="password", type=str)
    parser.add_argument('-s', '--salt', nargs=1, type=str, help='Salt to use')
    parser.add_argument('-o', '--out', nargs=1, type=str, help='Out Location')

    args = parser.parse_args()

    outputFile = args.out[0] if args.out else args.hashtable

    encodedSalt = args.salt[0].encode() if args.salt else os.urandom(16)
    print("Salt={}".format(encodedSalt))

    key = EncryptionHelpers.KeyFromPassword(args.password, encodedSalt)
    print("Generated Key {}".format(key))

    dat = None

    with open(args.hashtable, "rb+") as f:
        dat = f.read()

    # Decrypt
    raw = EncryptionHelpers.Decrypt(dat, EncryptionHelpers.LoadMachineKeys())

    # Encrypt
    enc = EncryptionHelpers.Encrypt(raw, key, encodedSalt)

    with open(outputFile, "wb+") as f:
        f.write(encodedSalt + enc)
