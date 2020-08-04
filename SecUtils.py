#!/usr/bin/env python3

import shutil
import sys
import os
import numpy
import argparse
import platform
from collections import Counter
from HashUtil import HashList
import math
import pandas
import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt

hashlist = HashList.CHashList()

imageTypes = [b'jpg', b'jpeg', b'png', b'cr2', b'bmp']
sourceImageTypes = [b"psd"]
movingImageTypes = [b'gif', b'mp4', b'mkv', b'webm', b'mov']
audioTypes = [b'flac', b'mp3', b'ogg', b'wav']
textTypes = [b'txt', b'rtf', b'doc', b'docx', b'pdf', b'md', b'odt', b'tex']
codeTypes = [b'cpp', b'js', b'h', b'dockerfile', b'vcxproj', b'sh', b'sln', b'gitignore', b'inl', b'def', b'ts', b'yaml', b'cs', b'java', b'hs', b'cmake', b'py']
artTypes = [b'zbp', b'zmt', b'zsc', b'zbp', b'ztl', b'zpr']
threeDimTypes = [b'rip', b'dds', b'fbx', b'tga', b'nif']
dataTypes = [b'json', b'7z', b'zip']
keyTypes = [b'pem']

def ClassifyTypes():
    indexList = []

    types = {
        "image": 0,
        "imageSources": 0,
        "movingImage": 0,
        "text": 0,
        "audio": 0,
        "code": 0,
        "art": 0,
        "3d": 0,
        "data": 0
        }

    others = []

    for i in hashlist.hashList:
        size = i[0]
        il = i[3][1]
        indexType = None
        if il in imageTypes:
            types["image"] += 1
            indexType = 0
        elif il in movingImageTypes:
            types["movingImage"] += 1
            indexType = 1
        elif il in textTypes:
            types["text"] += 1
            indexType = 2
        elif il in audioTypes:
            types["audio"] += 1
            indexType = 3
        elif il in artTypes:
            types["art"] += 1
            indexType = 4
        elif il in codeTypes:
            types["code"] += 1
            indexType = 5
        elif il in threeDimTypes:
            types["3d"] += 1
            indexType = 6
        elif il in dataTypes:
            types["data"] += 1
            indexType = 7
        elif il in sourceImageTypes:
            types["imageSources"] += 1
            indexType = 8
        else:
            others.append(il)

        if indexType:
            indexList.append(indexType)

    return types, others, indexList


def Bucketise(spread, scale, filterArray=None):
    buckets = numpy.zeros(spread)

    print("Bucket Limit = {} GiB".format((spread * scale) / (1024 ** 3)))

    array = hashlist.hashList

    if filterArray:
        print("Filtering")
        array = [array[x] for x in range(len(filterArray)) if filterArray[x] is not None]

    for i in array:
        scaled = i[0] / scale

        scaledBucket = math.floor(scaled)

        if scaledBucket >= buckets.shape[0] - 2:
            scaledBucket = buckets.shape[0] - 1

            print("Size is {} GiB".format(i[0] / 1024 ** 3))
            print("Scaled Size is {}".format(i[0] / scale))
            print("\tgoes in bucket: {}".format(scaledBucket))

        buckets[scaledBucket] += 1

    return buckets

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Generates File Identities with an option to quarantine duplicates")
    parser.add_argument('-t', '--hashtable', nargs=1, type=str, help='Location of hashtable')
    #parser.add_argument("--allow-quarantine", action="store_true")
    #parser.add_argument("--silent", action="store_true")
    #parser.add_argument("path", metavar="path", type=str)

    args = parser.parse_args()

    hashlist = HashList.CHashList(args.hashtable[0].encode() if args.hashtable else None)

    spread = (1024 ** 2) * 20
    scale = 1024

    classTypes, unclassedTypes, classIndices = ClassifyTypes()
    buckets = Bucketise(spread, scale)#, classIndices)

    rawFileSizeList = numpy.zeros(len(hashlist.hashList))
    
    for i in range(len(hashlist.hashList)):
        rawFileSizeList[i] = hashlist.hashList[i][0]

    print(Counter(unclassedTypes))

    classPd = pandas.DataFrame(classTypes, index=["Types"])
    classAx = classPd.plot.barh(figsize=(16,9))
    classFig = classAx.get_figure()
    #classFig, (classAx1, classAx2) = plt.subplots(2, 1, sharex=False, figsize=(16,18))
    #classAx1.barh(classPd.iloc[0:0], width=0.8)
    #classAx.set_ylabel("Number of Files")
    classAx.set_xscale("symlog")
    classAx.set_xlabel('Number of Files')
    
    classFig.savefig("classTypes.png")

    ax = plt.axes(label="World")
    ax.plot(numpy.arange(len(rawFileSizeList)), numpy.cumsum(numpy.sort(rawFileSizeList)) / (1024*1024*1024))
    fig = ax.get_figure()
    #ax.set_yscale("symlog")
    ax.set_xlim(left=-1)
    #ax.set_ylim(bottom=0)
    #ax.set_xscale("symlog", linthresh=4*16)
    ax.set_ylabel("Filesize (GiB) (Cumulative)")
    ax.set_xlabel("Files")
    fig.savefig('FileSize.png')
    
    ax = plt.axes(label="World2")
    ax.plot(numpy.arange(len(rawFileSizeList)), numpy.cumsum(rawFileSizeList) / (1024*1024*1024))
    fig = ax.get_figure()
    #ax.set_yscale("symlog")
    ax.set_xlim(left=-1)
    #ax.set_ylim(bottom=0)
    #ax.set_xscale("symlog", linthresh=4*16)
    ax.set_ylabel("Filesize (GiB) (Cumulative)")
    ax.set_xlabel("Files")
    fig.savefig('FileSizeUnsorted.png')

    pd = pandas.DataFrame(buckets)
    #ax = pd.plot(figsize=(16,9))
    ax = plt.axes(label="Hi")
    ax.plot(numpy.arange(len(buckets)), numpy.cumsum(buckets))
    fig = ax.get_figure()
    #ax.set_yscale("symlog")
    ax.set_xlim(left=-1)
    #ax.set_ylim(bottom=0)
    ax.set_xscale("symlog", linthresh=4*16)
    ax.set_ylabel("Number of Files (Cumulative)")
    ax.set_xlabel('Filesize (KiB)')
    fig.savefig('out.png')

    