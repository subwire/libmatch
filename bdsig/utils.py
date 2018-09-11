import os
import angr
import logging
from .lmd import LibMatchDescriptor
from .iocg import InterObjectCallgraph
from .libmatch import LibMatch


l = logging.getLogger("bdsig.utils")
l.setLevel("DEBUG")

PROJECT_KWARGS = {"load_options": {"rebase_granularity": 0x1000}}

def make_all_signatures(rootDir):
    if os.path.isfile(rootDir):
        l.info("Making signature for " + rootDir)
        LibMatchDescriptor.make_signature_dump(rootDir, **PROJECT_KWARGS)
    else:
        for dirName, subdirList, fileList in os.walk(rootDir):
            l.info('Found directory: %s' % dirName)
            for fname in fileList:
                if fname.endswith(".o"):
                    fullfname = os.path.join(dirName, fname)
                    l.info("Making signature for " + fullfname)
                    try:
                        LibMatchDescriptor.make_signature_dump(fullfname, **PROJECT_KWARGS)
                    except angr.errors.AngrCFGError:
                        l.warn("No executable data for %s, skipping" % fullfname)
                    except Exception as e:
                        l.exception("Could not make signature for " + fullfname)

def make_iocg(rootDir):
    lmds = set()
    if os.path.isfile(rootDir):
        l.info("Making signature for " + rootDir)
        lmds.add(LibMatchDescriptor.make_signature(rootDir, **PROJECT_KWARGS))
    else:
        for dirName, subdirList, fileList in os.walk(rootDir):
            l.info('Found directory: %s' % dirName)
            for fname in fileList:
                if fname.endswith(".o"):
                    fullfname = os.path.join(dirName, fname)
                    l.info("Making signature for " + fullfname)
                    try:
                        lmds.add(LibMatchDescriptor.make_signature(fullfname, **PROJECT_KWARGS))
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

def match_all_iocgs(lmd_path, rootDir):
    lmd = LibMatchDescriptor.load_path(lmd_path)
    candidates = []
    if os.path.isfile(rootDir):
        l.info("Checking IOCG for " + rootDir)
        try:
            iocg = InterObjectCallgraph.load_path(rootDir)
            lm = LibMatch(lmd, iocg)

            candidates.append(lm._second_order_matches)

            # TODO: implement .result_stats once matching is complete
            """
            r, matched = lm.result_stats()
            if r > 0.0:
            candidates.append((r, matched, fname))
            """
        except Exception as e:
            l.exception("Could not match signature for " + rootDir)
            raise
    else:
        for dirName, subdirList, fileList in os.walk(rootDir):
            l.info('Found directory: %s' % dirName)
            for fname in fileList:
                if fname.endswith(".iocg"):
                    fullfname = os.path.join(dirName, fname)
                    l.info("Checking IOCG for " + fullfname)
                    try:
                        iocg = InterObjectCallgraph.load_path(fullfname)
                        lm = LibMatch(lmd, iocg)

                        candidates.append(lm._second_order_matches)

                        # TODO: implement .result_stats once matching is complete
                        """
                        r, matched = lm.result_stats()
                        if r > 0.0:
                            candidates.append((r, matched, fname))
                        """
                    except Exception as e:
                        l.exception("Could not match signature for " + fullfname)
    return candidates
