#!/usr/bin/env python3

#####
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import platform
import uuid
import os # urandom

def KeyFromPassword(password: str, salt: bytes):
    # Expand Key
    provider = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        iterations=1000000,
        backend=default_backend()
    )

    return provider.derive(password.encode())

def _Hash(blob):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(blob)
    return digest.finalize()

def _GetCacheLocations():
    if platform.system() == "Windows":
        return os.path.join(os.environ["APPDATA"], "PyDeduplication")
    else:
        return os.path.join("~/.config", "PyDeduplication")
    

def _KeyCache(key):
    # Get cache location
    folderPath = _GetCacheLocations()

    # Check if it exists
    if not os.path.exists(folderPath):
        os.makedirs(folderPath)

        # Check again that the path exists
        # We should have errored if that failed, though
        if not os.path.exists(folderPath):
            raise RuntimeError("Failed to create folder")

    filePath = os.path.join(folderPath, "localkey")

    if os.path.exists(filePath):
        with open(filePath, "rb") as f:
            return f.read()
    else:
        with open(filePath, "wb") as f:
            f.write(key)

    return key

def _GetLinuxUUID():
    """Special function because invalidating hashtables on
bios update sounds awful"""

    # try dbus
    try:
        keyingMaterial = None

        with open("/var/lib/dbus/machine-id", "rb") as f:
            keyingMaterial = f.read().split(b"\n")[0]

        return _Hash(keyingMaterial)

    except Exception as e:
        print("DBus ID failed! ({}). Falling back".format(e))

        try:
            keyingMaterial = None

            # Okay, let's get ID from modalias
            with open("/sys/class/dmi/id/subsystem/id/modalias", "rb") as f:
                keyingMaterial = f.read()

            return _Hash(keyingMaterial)

        except Exception as e:
            print("ModAlias ID failed! ({}). Falling back".format(e))

    # So... We have no keys...
    # Go on, UUID, make my day
    key = _Hash(uuid.UUID(int=uuid.getnode()).bytes)
    return _KeyCache(key)

def _GetWindowsUUID():
    # Generate and write
    hashuuid =  _Hash(uuid.UUID(int=uuid.getnode()).bytes)

    return _KeyCache(hashuuid)

def LoadMachineKeys():
    """Load the key from the machine that we are on
Yes... I am aware that this is not really secure.
It's just to prevent whoopsies. """

    if platform.system() == "Windows":
        key = _GetWindowsUUID()
    else:
        key = _GetLinuxUUID()

    #print("Using UUID: {}".format(key))

    # Is there any point? The UUID isn't really secure anyway
    # kdf = KBKDFHMAC(
    #     algorithm=hashes.SHA3_256(),
    #     mode=Mode.CounterMode,
    #     length=32,
    #     rlen=4,
    #     llen=4,
    #     location=CounterLocation.BeforeFixed,
    #     label="PyDepulication",
    #     context=,
    #     fixed=None,
    #     backend=default_backend()
    # )

    return key


def Decrypt(blob: bytes, key: bytes, assoc: bytes = None):
    provider = AESGCM(key)
    iv = blob[:12]
    data = blob[12:]

    return provider.decrypt(iv, data, assoc)

def Encrypt(blob: bytes, key: bytes, assoc: bytes = None):
    """AEAD using AESGCM"""
    provider = AESGCM(key)
    iv = os.urandom(12)

    encBlob = provider.encrypt(iv, blob, assoc)

    return iv + encBlob