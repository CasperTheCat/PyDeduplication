import sys
import shlex
import shutil
import platform
import os
import re

def MoveFileToQuarantine(i, r, hostPath):
    #absp = os.path.join(r.encode(), p.encode())
    #movTarPart = os.path.join(os.path.abspath(os.path.join(args.path.encode(), "../.!Quarantine".encode())), t)
    #movTar = os.path.join(movTarPart, p.encode())

    movTarRoot = os.path.join(hostPath, i)


    # Move from i to Quarantine/i
    movTar = os.path.join("../.!Quarantine", i)

    movTarTarget = os.path.join(hostPath, movTar)

    if not os.path.exists(movTarTarget):
        os.makedirs(movTarTarget)

    if os.path.exists(movTarTarget):
        print("Moving\t{}\n   To: {}\n   Conflict: \"{}\"".format(movTarRoot, movTarTarget, r))
        shutil.move(movTarRoot, movTarTarget)

def GetCL(x):
    #s = shlex.split(x)
    s = x.split(" ")
    svar = ''.join(s[2:])
    svar = eval(svar).decode()
    return Sanitise(svar), 0

def GetEMP(x):
    s = x.split(" ")
    svar = ''.join(s[2:])
    svar = eval(svar).decode()
    print(svar)
    return Sanitise(s[2]), 0

def GetCOL(x):
    #x = x.replace("'", "\"")
    #s = shlex.split(x, posix=False)
    s = [p for p in re.split("( |\\\".*?\\\"|'.*?')", x) if p.strip()]
    return Sanitise(eval("".join(s[2:4])).decode()), Sanitise(eval("".join(s[6:])).decode())


def Sanitise(path):
    if platform.system() == "Windows":
        return ('/'.join(path.split("\\")))
    else:
        return path

with open(sys.argv[1], "r") as fileObj:
    #fileObj.seek(0)
    #fileObj.read(4096)
    data = fileObj.read().split("\n")
    
    if(len(sys.argv) > 3):
        filtered = [d for d in data if d.startswith("[CLE")]
        filterComs = [GetCL(f) for f in filtered]

        #print(filterComs[0])
        #print(1/0)

    else:
        filtered = [d for d in data if d.startswith("[COL")]
        filterComs = [GetCOL(f) for f in filtered]
        
        filtered = [d for d in data if d.startswith("[EMP")]
        filterComs = filterComs + [GetEMP(f) for f in filtered]

        #print(filterComs)

    #print(filterComs)


    for i in filterComs:
        if not (len(sys.argv) > 3):
            MoveFileToQuarantine(i[0], i[1], sys.argv[2])


    #print('\n'.join(filtered))

# with open(sys.argv[1], "r", encoding="utf-16-le") as fileObj:
#     #fileObj.seek(0)
#     #fileObj.read(4096)
#     data = fileObj.read().split("\n")
    
#     if(len(sys.argv) > 2):
#         filtered = [d for d in data if d.startswith("Skipping")]
#     else:
#         filtered = [d for d in data if d.startswith("Checked")]

#     print('\n'.join(filtered))