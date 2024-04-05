#!/usr/bin/env python3

import shutil
import sys
import os
import argparse
import platform
from HashUtil import HashList
from HashUtil import Utils
from HashUtil import Extensions
from enum import Enum
import queue

class EProcessPhase(Enum):
    PrimaryShortHashPass = 1
    SecondaryFullPass = 2
    ThreadJoin = 3

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
    elif arguments.zfs_block:
        print("[EXTENSION] 128KiB Block Enabled")
        HashExts.append(Extensions.EXT_128KiBShortHashBlock)

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

def ProcSingleFile(args, Root, FilePath, SharedHashList, SharedHashLock, LogLines):
    # Let's catagorise these
    f = FilePath.split(".")
    path = os.path.join(Root, FilePath)
    relp = os.path.relpath(path, os.path.abspath(args.path)).encode()
    ext = f[len(f) - 1].lower().encode()
    pathAsBytes = args.path.encode()

    try:
        IsElementKnown, ComputedShortHash, ComputedLongHash, ComputedPerceptualHash = SharedHashList.IsElementKnownWithHash(pathAsBytes, relp, ext, allowLongHashes=(not (args.fast or args.short_hash)), minimumLogSeverity=Utils.ELogSeverity.Suppress if args.silent else Utils.ELogSeverity.Info, useRawHashes=args.raw, mutex=SharedHashLock, logList=LogLines)
        if not IsElementKnown:
            if not args.silent:
                LogLines.append(
                    Utils.FormatLog(Utils.ELogSeverity.Info, "[ADDITION] File: {}".format(relp))
                )
            SharedHashList.AddElement(pathAsBytes, relp, ext, useLongHash=(not args.short_hash), useRawHashes=args.raw, disableCheckpoint=True, PrecomputedShortHash=ComputedShortHash, PrecomputedLongHash=ComputedLongHash, PrecomputedPerceptualHash=ComputedPerceptualHash, mutex=SharedHashLock)
        else:
            if args.allow_quarantine:
                MoveFileToQuarantine(Root, (FilePath, ext), args)  
    except KeyboardInterrupt as kbi:
        raise kbi
    except Exception as e:
        LogLines.append(
            Utils.FormatLog(Utils.ELogSeverity.Error, "Error on file {}: {}".format(FilePath, e))
        )


def PrimaryPhase(args, pathAsBytes, relp, ext, fileSize, SharedHashList, LogLines):
    # Short Hash here
    ShortHash = SharedHashList.PrecomputeShortHash(pathAsBytes, relp, ext, fileSize, args.raw)
    if ShortHash is None:
        if not args.silent:
            LogLines.append(
                Utils.FormatLog(Utils.ELogSeverity.Info, "[EMPTY] File {} is empty".format(SharedHashList._SanitisePath(relp)))
            )
    return ShortHash

def SecondaryPhase(args, pathAsBytes, relp, ext, fileSize, SharedHashList, LogLines):
    return SharedHashList.PrecomputeLongHash(pathAsBytes, relp, ext, fileSize, args.raw)

def PerceptualPhase(args, pathAsBytes, relp, ext, fileSize, SharedHashList, LogLines):
    #TODO
    return SharedHashList.PrecomputeLongHash(pathAsBytes, relp, ext, fileSize, args.raw)

def ProcessThreadMain(ThreadID, TaskQueue, OutQueue, GlobalHashList, LogQueue):
    LocalLogs = []
    LocalResults = []

    while(True):
        Task = TaskQueue.get()
        if Task is None:
            TaskQueue.task_done()
            return

        TaskType, TaskArgs = Task
        if TaskType == EProcessPhase.PrimaryShortHashPass:
            args, pathAsBytes, relp, ext, fileSize = TaskArgs
            ShortHash = PrimaryPhase(args, pathAsBytes, relp, ext, fileSize, GlobalHashList, LocalLogs)

            if ShortHash is not None:
                # Non-locked read-only hash check
                UseLongComparison = not (args.fast or args.short_hash)
                if UseLongComparison:
                    # Bypass checking and directly add since it's irrelevant to the process here
                    LocalResults.append((EProcessPhase.PrimaryShortHashPass, (args, pathAsBytes, relp, ext, fileSize, ShortHash)))
                else:
                    # Check
                    DidCollide = GlobalHashList._DoesShortHashCollide(fileSize, (relp, ext), ShortHash, Utils.ELogSeverity.Info, LocalLogs)
                    if not DidCollide:
                        LocalResults.append((EProcessPhase.PrimaryShortHashPass, (args, pathAsBytes, relp, ext, fileSize, ShortHash)))
        elif TaskType == EProcessPhase.SecondaryFullPass:
            args, pathAsBytes, relp, ext, fileSize, ShortHash = TaskArgs
            LongHash = SecondaryPhase(args, pathAsBytes, relp, ext, fileSize, GlobalHashList, LocalLogs)

            if LongHash is not None:
                UseLongComparison = not (args.fast or args.short_hash)
                if UseLongComparison:
                    DidCollide = GlobalHashList._DoesLongHashCollide(fileSize, (relp, ext), LongHash, Utils.ELogSeverity.Info, LocalLogs)

                    if not DidCollide:
                        LocalResults.append((EProcessPhase.SecondaryFullPass, (args, pathAsBytes, relp, ext, fileSize, ShortHash, LongHash)))

                else:
                    LocalResults.append((EProcessPhase.SecondaryFullPass, (args, pathAsBytes, relp, ext, fileSize, ShortHash, LongHash)))
        elif TaskType == EProcessPhase.ThreadJoin:
            # Flush logs
            #LogThreadLock.acquire()
            LogQueue.put(LocalLogs.copy()) # Maybe not needed, but force the copy. I don't trust Python :P
            #LogThreadLock.release()
            OutQueue.put(LocalResults.copy())

            LogQueue.put([Utils.FormatLog(Utils.ELogSeverity.Verbose, "[THREADING] Thread {} Shutdown. Reason: {}".format(ThreadID, TaskArgs))])
            TaskQueue.task_done()
            return
        else:
            TaskQueue.task_done()
            return

        TaskQueue.task_done()

        if len(LocalResults) > 16384:
            OutQueue.put(LocalResults.copy())
            LocalResults = []

        if len(LocalLogs) > 1024:
            # Flush
            LogQueue.put(LocalLogs.copy())
            LocalLogs = []

def LogThreadMain(LogQueue, LogLevel):
    while(True):
        LogEntry = LogQueue.get()
        if LogEntry is None:
            LogQueue.task_done()
            return

        for Severity, Line in LogEntry:
            # Shall we print?
            if Severity.value >= LogLevel.value:
                if Severity == Utils.ELogSeverity.Error or Severity == Utils.ELogSeverity.Fatal:
                    print(Line, file=sys.stderr)
                else:
                    print(Line)

            if Severity == Utils.ELogSeverity.Fatal:
                raise Exception(Line)

        LogQueue.task_done()

def ConfigureThreadPipeline(nThreads, InQueue, OutQueue, TaskName, LogQueue, GlobalHashList):
    # Spawn Pool
    # Spawn Pool
    JoinReason = "{} Fence".format(TaskName)
    ThreadPool = []
    LogQueue.put([Utils.FormatLog(Utils.ELogSeverity.Verbose, "[THREADING] Spawning {} {} Threads".format(nThreads, TaskName))])
    for i in range(nThreads):
        ThatThread = Thread(target=ProcessThreadMain, args=[i, InQueue, OutQueue, GlobalHashList, LogQueue])
        ThreadPool.append(ThatThread)
        ThatThread.start()

    return (ThreadPool, JoinReason)

def AwaitPipelineCompletion(ThreadPipeline, InQueue: queue):
    ThreadPool, JoinReason = ThreadPipeline
    for Th in ThreadPool:
        InQueue.put((EProcessPhase.ThreadJoin, JoinReason))

    for Th in ThreadPool:
        Th.join()

    # Return the queue to empty
    while not InQueue.empty:
        InQueue.get()
        InQueue.task_done()


def GetFileTasks(args):
    for r, d, p in os.walk(args.path):
        d[:] = [x for x in d if x not in excludeDirs]
        p[:] = [x for x in p if GetExtension(x) not in excludeFileTypes]

        if ".skipfolder" in p:
            d[:] = []#[x for x in d]
            Utils.PrintPrettyLog(Utils.ELogSeverity.Verbose, "Skipping Below {}".format(r))
            continue

        for fi in p:
            # Let's catagorise these
            f = fi.split(".")
            path = os.path.join(r, fi)
            relp = os.path.relpath(path, os.path.abspath(args.path)).encode()
            ext = f[len(f) - 1].lower().encode()
            pathAsBytes = args.path.encode()

            fullPath = os.path.join(pathAsBytes, relp)
            fileSize = os.path.getsize(fullPath)

            yield (args, pathAsBytes, relp, ext, fileSize)

if __name__ == "__main__":
    from threading import Thread, Lock, Semaphore, Condition
    import time
    
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
    parser.add_argument('-zb', '--zfs-block', action="store_true", help='Use 128KiB short hash block size to align to common ZFS parameters, up from 4Ki')
    parser.add_argument('-mb', '--medium-block', action="store_true", help='Use 1MiB short hash block size, up from 4Ki')
    parser.add_argument('-lb', '--large-block', action="store_true", help='Use 16MiB short hash block size, up from 4Ki or 1Mi')
    parser.add_argument('-cpus', '--threads', nargs=1,  metavar="nThreads", type=int, help='Number of Threads. Improves performance when IO bound. Defaults to 1. (Set 0 to use all CPUs. Scan Threads will be set to 4x the value set here.).')
    parser.add_argument('-scpus', '--scan-threads', nargs=1,  metavar="nThreads", type=int, help='Number of Threads. Improves performance when IO bound. Defaults to 1. (Set 0 to use all 4x total CPU count).')
    parser.add_argument('-fcpus', '--full-threads', nargs=1,  metavar="nThreads", type=int, help='Number of Threads. Improves performance when IO bound. Defaults to 1. (Set 0 to use all CPUs).')
    parser.add_argument("path", metavar="path", type=str)

    args = parser.parse_args()

    # Sanity Short and non-raw
    if args.short_hash and not args.raw:
        Utils.PrintPrettyLog(Utils.ELogSeverity.Warn, "Using short hashes without specifing the raw hash mode may lead to false positive collisions.")

    if args.allow_quarantine and args.short_hash:
        Utils.PrintPrettyLog(Utils.ELogSeverity.Warn, "Using quarantine without the added safety of full-file hashes is not advised.")
        if not args.raw:
            Utils.PrintPrettyLog(Utils.ELogSeverity.Fatal, "Quarantining enabled without raw or full-file hashes. This configuration WILL result in quarantining files in error. Either specify raw hashes or renable full-file hashing!")

    if not os.path.exists(args.path):
        Utils.PrintPrettyLog(Utils.ELogSeverity.Fatal, "Directory \"{}\" does not exist".format(
            args.path
        ))

    if not IsDriveSafe(args.path, "./") and args.allow_quarantine:
        Utils.PrintPrettyLog(Utils.ELogSeverity.Fatal, "Path is a parent of the directory this script is in!")

    pathAsBytes = args.path.encode()

    encodedHashtable = args.hashtable[0].encode() if args.hashtable else None

    WantedExtensions = GetHashExtensions(args)

    hashlist = HashList.CHashList(encodedHashtable, WantedExtensions)
    hashlist.Prune(pathAsBytes, dry_run=False, minimumLogSeverity=Utils.ELogSeverity.Suppress if args.silent else Utils.ELogSeverity.Info)

    UseLongComparison = not (args.fast or args.short_hash)

    LogLevel = Utils.ELogSeverity.Info
    # VERBOSE
    if args.silent:
        LogLevel = Utils.ELogSeverity.Suppress

    # Threading
    BaseThreadCount = 1
    if args.threads and len(args.threads) == 1:
        BaseThreadCount = args.threads[0] if args.threads[0] > 0 else os.cpu_count()

    # Threading
    ScanThreadLimit = BaseThreadCount * 4
    if args.scan_threads and len(args.scan_threads) == 1:
        ScanThreadLimit = args.scan_threads[0] if args.scan_threads[0] > 0 else os.cpu_count() * 4

    # Threading
    ProcThreadLimit = BaseThreadCount
    if args.full_threads and len(args.full_threads) == 1:
        ProcThreadLimit = args.full_threads[0] if args.full_threads[0] > 0 else os.cpu_count()

    CandidateEntries = []
    ThreadPool = []
    LoggerThread = None
    GlobalHashLock = Lock()
    TaskQueue = queue.Queue()
    ResultQueue = queue.Queue()
    LongQueue = queue.Queue()
    LogQueue = queue.Queue()

    # Spawn Logging Thread
    LoggerThread = Thread(target=LogThreadMain, args=[LogQueue, LogLevel])
    LoggerThread.start()

    # Stats
    STATS_TotalShortData = 0
    STATS_TotalLongData = 0
    STATS_ShortTime = 0
    STATS_LongTime = 0

    try:
        # Short Hash
        ShortHashPipeline = ConfigureThreadPipeline(ScanThreadLimit, TaskQueue, ResultQueue, "ShortHashQueue", LogQueue, hashlist)

        ShortStart = time.time()

        for ShortHashTask in GetFileTasks(args):
            STATS_TotalShortData += ShortHashTask[4]
            TaskQueue.put((EProcessPhase.PrimaryShortHashPass, ShortHashTask))

        AwaitPipelineCompletion(ShortHashPipeline, TaskQueue)

        STATS_ShortTime = time.time() - ShortStart


        # Long Hash
        LongHashPipeline = ConfigureThreadPipeline(ProcThreadLimit, TaskQueue, LongQueue, "LongHashQueue", LogQueue, hashlist)

        LongStart = time.time()

        KnownReductionHashes = {}
        while not ResultQueue.empty():
            T = ResultQueue.get()

            for TaskPhase, TaskArgs in T:
                args, pathAsBytes, relp, ext, fileSize, ShortHash = TaskArgs
                STATS_TotalLongData += fileSize

                saneRelPath = hashlist._SanitisePath(relp)

                if UseLongComparison or not ShortHash in KnownReductionHashes:
                    TaskQueue.put((EProcessPhase.SecondaryFullPass, (args, pathAsBytes, relp, ext, fileSize, ShortHash)))
                    KnownReductionHashes[ShortHash] = saneRelPath
                elif not UseLongComparison and ShortHash in KnownReductionHashes and not args.silent:
                    LogQueue.put([Utils.FormatLog(Utils.ELogSeverity.Info, "[COLLISION] File {} collided with {}".format(saneRelPath, KnownReductionHashes[ShortHash]))])

            ResultQueue.task_done()

        AwaitPipelineCompletion(LongHashPipeline, TaskQueue)

        STATS_LongTime = time.time() - LongStart

        while not LongQueue.empty():
            T = LongQueue.get()

            for TaskPhase, TaskArgs in T:
                args, pathAsBytes, relp, ext, fileSize, ShortHash, LongHash = TaskArgs

                # # DEBUG ONLY
                # if hashlist.IsElementKnown(pathAsBytes, relp, ext, True, True):
                #     Utils.PrintPrettyLog(Utils.ELogSeverity.Fatal, "File \"{}\" does not get handled correctly".format(
                #         os.path.join(pathAsBytes, relp)
                #     ))

                # hashlist.AddElement(
                #     pathAsBytes,
                #     relp,
                #     ext,
                #     useLongHash=(not args.short_hash),
                #     useRawHashes=args.raw,
                #     disableCheckpoint=True,
                #     PrecomputedShortHash=ShortHash,
                #     PrecomputedLongHash=LongHash,
                #     PrecomputedPerceptualHash=None
                # )

                saneRelPath = hashlist._SanitisePath(relp)

                if hashlist._IsPathKnown(relp, ext):
                    # Interesting
                    LogQueue.put([Utils.FormatLog(Utils.ELogSeverity.Info, "[MODIFIED] File {} has been modified".format(saneRelPath))])
                    hashlist.UpdateHashedElement(
                        saneRelPath,
                        ext,
                        fileSize,
                        ShortHash,
                        LongHash,
                        None
                    )
                else:
                    hashlist.AddHashedElement(
                        saneRelPath,
                        ext,
                        fileSize,
                        ShortHash,
                        LongHash,
                        None
                    )


            LongQueue.task_done()

        # Write the list out
        hashlist.Write()
    finally:
        LogQueue.put(None)
        LoggerThread.join()

        # print Stats
        if not args.silent:
            if STATS_ShortTime > 0:
                print("[STATS][SHORT] Processed {} in {}: {:.2f} MiB/s".format(STATS_TotalShortData, STATS_ShortTime, (STATS_TotalShortData / (1024 * 1024)) / STATS_ShortTime))
            if STATS_LongTime > 0:
                print("[STATS][LONG] Processed {} in {}: {:.2f} MiB/s".format(STATS_TotalLongData, STATS_LongTime, (STATS_TotalLongData / (1024 * 1024)) / STATS_LongTime))
