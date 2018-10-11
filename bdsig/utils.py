import os
import angr
import logging
from .lmd import LibMatchDescriptor
from .iocg import InterObjectCallgraph
from .libmatch import LibMatch
from collections import defaultdict

l = logging.getLogger("bdsig.utils")
l.setLevel("DEBUG")

PROJECT_KWARGS = {"load_options": {"rebase_granularity": 0x1000}}


def collect_best_matches_for_library(binary_filename, libDir):
    # Build the library signature
    make_iocg(libDir)
    iocg_path = libDir.rstrip(os.path.sep) + ".iocg"

    # Build the digested version of the binary
    if isinstance(binary_filename, str):
        lmd_name = LibMatchDescriptor.make_signature_dump(binary_filename)
    elif isinstance(binary_filename, angr.Project):
        lmd_name = LibMatchDescriptor(binary_filename)
    # Match it!
    results = match_all_iocgs(lmd_name, iocg_path)
    for matches in results:
        score_matches(lmd_name, matches)

    print("###################################")
    return postprocess_matches(lmd_name, results)




def object_context_matching(lmd_name, matches):
    target_lmd = LibMatchDescriptor.load_path(target_lmd_name)

    # now check around:
    for f_addr, match_infos, in matches.items():
        # For every imprecise match
        if len(match_infos > 1):
            candidate_objs = None
            # Are either of the neighboring functions from an object in our candidates?

def matches_list(matches):
    return [(x, y) for x, y in matches.items()]

def get_previous_match(f_addr, precise_matches):
    sorted_matches = sorted(precise_matches, key=lambda m: m[0])
    idx = None
    for i, m in enumerate(sorted_matches):
        a, mx = m
        if f_addr == a:
            idx = i
            break
    assert idx is not None
    if idx == 0:
        return None
    prev_a, prev_mx = sorted_matches[idx-1]
    if len(prev_mx) == 1: # is the match precise
        return prev_a, prev_mx
    return None


def get_next_match(f_addr, precise_matches):
    sorted_matches = sorted(precise_matches, key=lambda m: m[0])
    idx = None
    for i, m in enumerate(sorted_matches):
        a, mx = m
        if f_addr == a:
            idx = i
            break
    assert idx is not None
    if idx == len(sorted_matches) - 1:
        return None
    next_a, next_mx = sorted_matches[idx+1]
    if len(next_mx) == 1: # is the match precise
        return next_a, next_mx
    return None

from clint.textui.colored import red, green, yellow
def score_matches(target_lmd_name, matches):
    if isinstance(target_lmd_name, LibMatchDescriptor):
        target_lmd = target_lmd_name
    else:
        target_lmd = LibMatchDescriptor.load_path(target_lmd_name)
    precise_matches = 0
    imprecise_matches = 0
    incorrect_matches = 0
    missing = 0
    total_syms = len(target_lmd.viable_symbols)
    ignored = 0
    for sym in target_lmd.viable_symbols:
        f_addr = sym.rebased_addr
        if f_addr in target_lmd.banned_addrs:
            ingored += 1
            print("%#08x => Junk" % (f_addr))
        elif f_addr in matches:
            match_infos = matches[f_addr]
            if len(match_infos) == 1:
                for lib, lmd, match in match_infos:
                    obj_func_addr = match.function_b.addr
                    sym_name = lmd.function_manager.get_by_addr(obj_func_addr).name
                    if sym_name == sym.name:
                        print(green("%#08x => %s:%s(%f) [Correct!] in %s" % (f_addr, lib, sym_name, match.similarity_score, lmd.filename)))
                        precise_matches += 1
                    else:
                        print(red("%#08x => %s:%s(%f) [WRONG, %s] in %s" % (f_addr, lib, sym_name, match.similarity_score, sym.name, lmd.filename)))
                        incorrect_matches += 1
            else:
                imprecise_matches += 1
                print(yellow("%#08x" % f_addr))
                for lib, lmd, match in match_infos:
                    obj_func_addr = match.function_b.addr
                    sym_name = lmd.function_manager.get_by_addr(obj_func_addr).name
                    if sym_name == sym.name:
                        print(green("\t=> %s:%s(%f) in %s" % (lib, sym_name, match.similarity_score, lmd.filename)))
                    else:
                        print(yellow("\t=> %s:%s(%f) in %s" % (lib, sym_name, match.similarity_score, lmd.filename)))
        else:
            missing += 1
            print(red("%#08x => %s(UNMATCHED)" % (f_addr, sym.name)))

    print("Matched symbols: %d" % precise_matches)
    print("Missing symbols: %d" % missing)
    print("Incorrect symbols: %d" % incorrect_matches)
    print("Imprecise matches: %d" % imprecise_matches)
    print("Total symbols: %d " % total_syms)
    print("Hit rate: %f" % (precise_matches / total_syms))
    print("Error rate: %f" % (incorrect_matches / total_syms))
    print("Collision rate: %f" % (imprecise_matches / total_syms))


def print_matches(target, lmd_name, matches):
    if isinstance(target_lmd_name, LibMatchDescriptor):
        target_lmd = target_lmd_name
    else:
        target_lmd = LibMatchDescriptor.load_path(target_lmd_name)
    for f_addr, match_infos in matches.items():
        if target_lmd.symbol_for_addr(f_addr):
            # For easier scoring
            s = target_lmd.symbol_for_addr(f_addr)
            print("Function at %#08x[%s]:" % (f_addr, s.name))
        else:
            print("Function at %#08x:" % f_addr)
        for lmd, match in match_infos:
            obj_func_addr = match.function_b.addr
            sym_name = lmd.function_manager.get_by_addr(obj_func_addr).name
            print("[%f] %s(%#08x) in %s" % (match.similarity_score, sym_name, obj_func_addr, lmd.filename))


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
                        l.warning("No executable data for %s, skipping" % fullfname)
                    except Exception as e:
                        l.exception("Could not make signature for " + fullfname)

    l.info("Making IOCG")
    iocg = InterObjectCallgraph(lmds)
    directory = os.path.dirname(os.path.abspath(rootDir))
    filename = os.path.basename(os.path.abspath(rootDir)) + ".iocg"
    iocg.dump_path(os.path.join(directory, filename))
    l.info("Done")


def match_all_iocgs(lmd_path, rootDir):
    if isinstance(lmd_path, LibMatchDescriptor):
        lmd = lmd_path
    else:
        lmd = LibMatchDescriptor.load_path(lmd_path)
    candidates = []
    if os.path.isfile(rootDir):
        l.info("Checking IOCG for " + rootDir)
        try:
            iocg = InterObjectCallgraph.load_path(rootDir)
            lm = LibMatch(lmd, iocg)

            candidates.append(lm._candidate_matches)

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
