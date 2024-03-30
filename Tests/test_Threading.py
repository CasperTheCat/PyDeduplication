#!/usr/bin/env python3

import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList
from HashUtil import EncryptionHelpers
from HashUtil import Utils
from HashUtil import Extensions
from threading import Thread, Lock
import queue

def ProcSingleFile(GlobalPath, Root, FilePath, SharedHashList, SharedHashLock, LogLines):
    # Let's catagorise these
    f = FilePath.split(".")
    path = os.path.join(Root, FilePath)
    relp = os.path.relpath(path, os.path.abspath(GlobalPath)).encode()
    ext = f[len(f) - 1].lower().encode()
    pathAsBytes = GlobalPath.encode()

    try:
        IsElementKnown, ComputedShortHash, ComputedLongHash, ComputedPerceptualHash = SharedHashList.IsElementKnownWithHash(pathAsBytes, relp, ext, allowLongHashes=False, minimumLogSeverity=Utils.ELogSeverity.Suppress, useRawHashes=True, mutex=SharedHashLock, logList=LogLines)
        if not IsElementKnown:
            LogLines.append(
                Utils.FormatLog(Utils.ELogSeverity.Info, "[ADDITION] File: {}".format(relp))
            )
            SharedHashList.AddElement(pathAsBytes, relp, ext, useLongHash=True, useRawHashes=True, disableCheckpoint=True, PrecomputedShortHash=ComputedShortHash, PrecomputedLongHash=ComputedLongHash, PrecomputedPerceptualHash=ComputedPerceptualHash, mutex=SharedHashLock)
    except KeyboardInterrupt as kbi:
        raise kbi
    except Exception as e:
        LogLines.append(
            Utils.FormatLog(Utils.ELogSeverity.Error, "Error on file {}: {}".format(FilePath, e))
        )

def ProcessThreadMain(TaskQueue, GlobalThreadLock):
    LocalLogs = []

    while(True):
        Task = TaskQueue.get()
        if Task is None:
            TaskQueue.task_done()
            return

        Path, Root, FilePath, SharedHashList = Task
        ProcSingleFile(Path, Root, FilePath, SharedHashList, GlobalThreadLock, LocalLogs)
        TaskQueue.task_done()

def PopulateTableWithGivenThreadCount(HashList, nThreads, TestPath):
    WaitingTasks = []
    ThreadPool = []
    GlobalHashLock = Lock()
    TaskQueue = queue.Queue()

    for i in range(nThreads):
        ThatThread = Thread(target=ProcessThreadMain, args=[TaskQueue, GlobalHashLock])
        ThreadPool.append(ThatThread)
        ThatThread.start()

    try:
        for r, d, p in os.walk(TestPath):
            for fi in p:
                TaskQueue.put((TestPath, r, fi, HashList))
    except:
        raise Exception("Test Failed")
    finally:
        for Th in ThreadPool:
            TaskQueue.put(None)

        for Th in ThreadPool:
            Th.join()


def test_ThreadedTableEqualsUnthreadedTable():
    SingleThreadHashlist = HashList.CHashList(b"SingleThread.ht")
    SixteenThreadHashlist = HashList.CHashList(b"SixteenThread.ht")

    # Add some files
    #assert(not os.path.abspath("./"))
    PopulateTableWithGivenThreadCount(SingleThreadHashlist, 1, "./TestHT")
    PopulateTableWithGivenThreadCount(SixteenThreadHashlist, 16, "./TestHT")

    HasMissingItem = False
    # Compare
    for sz, shs, lhs, nm, ph in SingleThreadHashlist.hashList:
        if not SixteenThreadHashlist._DoesLongHashCollide(sz, nm, lhs, Utils.ELogSeverity.Suppress):
            HasMissingItem = True

    for sz, shs, lhs, nm, ph in SixteenThreadHashlist.hashList:
        if not SingleThreadHashlist._DoesLongHashCollide(sz, nm, lhs, Utils.ELogSeverity.Suppress):
            HasMissingItem = True

    assert(not HasMissingItem)
    return
