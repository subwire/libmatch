import os
import angr
import logging
from .lmd import LibMatchDescriptor
from .iocg import InterObjectCallgraph


l = logging.getLogger("bdsig.utils")
l.setLevel("DEBUG")

def make_all_signatures(rootDir):
    if os.path.isfile(rootDir):
        l.info("Making signature for " + rootDir)
        LibMatchDescriptor.make_signature_dump(rootDir, load_options={"rebase_granularity": 0x1000})
    else:
        for dirName, subdirList, fileList in os.walk(rootDir):
            l.info('Found directory: %s' % dirName)
            for fname in fileList:
                if fname.endswith(".o"):
                    fullfname = os.path.join(dirName, fname)
                    l.info("Making signature for " + fullfname)
                    try:
                        LibMatchDescriptor.make_signature_dump(fullfname, load_options={"rebase_granularity": 0x1000})
                    except angr.errors.AngrCFGError:
                        l.warn("No executable data for %s, skipping" % fullfname)
                    except Exception as e:
                        l.exception("Could not make signature for " + fullfname)

def make_iocg(rootDir):
    lmds = set()
    if os.path.isfile(rootDir):
        l.info("Making signature for " + rootDir)
        lmds.add(LibMatchDescriptor.make_signature(rootDir, load_options={"rebase_granularity": 0x1000}))
    else:
        for dirName, subdirList, fileList in os.walk(rootDir):
            l.info('Found directory: %s' % dirName)
            for fname in fileList:
                if fname.endswith(".o"):
                    fullfname = os.path.join(dirName, fname)
                    l.info("Making signature for " + fullfname)
                    try:
                        lmds.add(LibMatchDescriptor.make_signature(fullfname, load_options={"rebase_granularity": 0x1000}))
                    except angr.errors.AngrCFGError:
                        l.warn("No executable data for %s, skipping" % fullfname)
                    except Exception as e:
                        l.exception("Could not make signature for " + fullfname)

    l.info("Making IOCG")
    iocg = InterObjectCallgraph(lmds)
    directory = os.path.dirname(os.path.abspath(rootDir))
    filename = os.path.basename(os.path.abspath(rootDir)) + ".iocg"
    iocg.dump_path(os.path.join(directory, filename))
    l.info("Done")

def match_all_iocgs(lmd, rootDir):
    candidates = []
    for dirName, subdirList, fileList in os.walk(rootDir):
        l.info('Found directory: %s' % dirName)
        for fname in fileList:
            if fname.endswith(".iocg"):
                fullfname = os.path.join(dirName, fname)
                l.info("Checking IOCG for " + fullfname)
                try:
                    iocg = InterObjectCallgraph.load_path(fullfname)
                    lm = iocg.match_against(lmd)
                    r, matched = lm.result_stats()
                    if r > 0.0:
                        candidates.append((r, matched, fname))
                except Exception as e:
                    l.exception("Could not match signature for " + fullfname)
    return candidates
