import logging
from .iocg import InterObjectCallgraph
from .lmd import LibMatchDescriptor
from .functiondiff import FunctionDiff
from collections import defaultdict

l = logging.getLogger("bdsig.libmatch")
l.setLevel("DEBUG")

class LibMatch(object):
    def __init__(self, binary_lmd, iocg):
        """
        :param binary_lmd: The LibMatchDescriptor of the target binary
        :param lib_lmds: An iterable of LibMatchDescriptors corresponding to libraries
        """
        self.binary_lmd = binary_lmd
        self.iocg = iocg
        self.lib_lmds = iocg.lib_lmds

        self._first_order_matches = {l: None for l in self.lib_lmds}
        self._second_order_matches = {l: None for l in self.lib_lmds}

        self._compute()

    @classmethod
    def _first_order_heuristic(self, lib_attrs, bin_attrs):
        """
        The heuristic to use to determine whether or not a given tuple of attrs from a lib func
        should match with a given tuple of attrs from a bin func.
        """
        # TODO: perfect matching
        return lib_attrs == bin_attrs

    def _compute_first_order_matches(self, lib):
        """
        Find matches between a lib and the target binary based purely on function attribute tuples.
        """
        self._first_order_matches[lib] = {}
        for faddr in lib.viable_functions:
            # match the lib func against the binary if the first order heuristic passes
            attrs = lib.function_attributes[faddr]
            results = {bin_faddr for bin_faddr, bin_attrs in self.binary_lmd.function_attributes.items()
                       if self._first_order_heuristic(attrs, bin_attrs)}
            self._first_order_matches[lib][faddr] = results

    @classmethod
    def _second_order_heuristic(cls, binary_lmd, lib_lmd, binary_faddr, lib_faddr):
        """
        The heuristic to use to determine whether or not two functions are approximately the same
        based on the FunctionDiff implementation.
        """
        lib_func = lib_lmd.normalized_functions[lib_faddr]
        bin_func = binary_lmd.normalized_functions[binary_faddr]
        # TODO: perfect matching
        return FunctionDiff(binary_lmd, lib_lmd, bin_func, lib_func)

    def _compute_second_order_matches(self, lib):
        """
        Refine matches between a lib and the target binary based purely on the FunctionDiff method.
        """
        self._second_order_matches[lib] = {}
        for faddr, potential_matches in self._first_order_matches[lib].items():
            for maddr in potential_matches:
                fd = self._second_order_heuristic(self.binary_lmd, lib, maddr, faddr)
                if fd.probably_identical:
                    self._second_order_matches[lib][faddr] = (maddr, fd)

    def _postprocess_second_order_matches(self):

        # Gather the matches based on the functions in the original binary:
        matches = defaultdict(list)
        #for lib_res in self._second_order_matches:
        for obj_lmd, obj_res in self._second_order_matches.items():
            for obj_func_addr, match in obj_res.items():
                if match:
                    target_addr, match_info = match
                    if len(matches[target_addr]) > 0:
                        # A collision! But is it a real one?
                        # Did we match better?
                        prev_lmd, prev_match_info = matches[target_addr][0]
                        if match_info.similarity_score > prev_match_info.similarity_score:
                            # Better match
                            matches[target_addr] = [(obj_lmd, match_info)]
                        elif match_info.similarity_score == prev_match_info.similarity_score:
                            matches[target_addr].append((obj_lmd, match_info))
                        else:
                            continue  # Worse match, ignore
                    else:
                        matches[target_addr].append((obj_lmd, match_info))
        self._candidate_matches = matches

    def _compute_third_order(self):
        self._postprocess_second_order_matches()
        for f_addr, matches in self._candidate_matches.items():
            self._narrow_third_order(f_addr, matches)

    def _narrow_third_order(self, f_addr, matches):
        if len(matches) == 1:
            # Perfect match! cannot refine
            return
        # Get the iocg entry for each candidate match
        target_func = list(matches)[0][1].function_a
        target_callees = []
        for from_block, callee in target_func.call_sites.items():
            if len(callee) > 1:
                l.error("More than one callee in a callsite, that's weird: %#008x %s" % (from_block.addr, repr(target_func.call_sites)))
            callee = callee[0]
            if not self.binary_lmd.loader.main_object.contains_addr(callee):
                # A jumpout! Fuck.
                callee_name = "UnresolvableCallTarget"
                target_callees.append((callee, callee_name))
            elif callee not in self._candidate_matches or len(self._candidate_matches[callee]) == 0:
                l.error("Cannot disambiguate function at %#08x, unmatched call to %#08x" % (f_addr, callee))
                return  # We're fucked
            else:
                callee_matches = self._candidate_matches[callee]
                if len(callee_matches) > 1:
                    l.error("Recursively resolving %#08x" % callee)
                    self._narrow_third_order(callee, callee_matches)
                m_lmd, m_fd = callee_matches[0]
                callee_name = m_lmd.symbol_for_addr(m_fd.function_b.addr).name
                target_callees.append((callee, callee_name))
        if not target_callees:
            l.error("No calls in function %#08x, cannot disambiguate" % f_addr)
            return

        # For each possible match
        self._candidate_matches[f_addr] = []
        l.debug("Resolving Function %#08x" % f_addr)
        for match_lmd, match_diff in matches:
            match_name = match_diff.function_b.name
            # Get the addresses of each function that library calls.
            lib_callees = [lol[0] for lol in match_diff.function_b.call_sites.values()]
            for targ_callee, lib_callee in zip(target_callees, lib_callees):
                targ_callee_addr, targ_callee_name = targ_callee
                lib_callee_name = match_lmd.symbol_for_addr(lib_callee).name
                if targ_callee_name == "UnresolvableCallTarget":
                    l.debug("Ignoring unresolvable call to %#08x" % targ_callee_addr)
                    pass
                if targ_callee_name != lib_callee_name:
                    l.debug("\tRuling out %s due to mismatched call (%s != %s)" % (match_name, targ_callee_name, lib_callee_name))
                    break
            else:
                self._candidate_matches[f_addr].append((match_lmd, match_diff))
                l.error("Resolved call to %#08x to %s via callgraph" % (f_addr, match_name))
                

    def _compute(self):
        """
        Compute everything, hopefully resulting in matches!
        """
        # first, find all first order matches (matches depending only on the attr tuples)
        for lib in self.lib_lmds:
            self._compute_first_order_matches(lib)

        for lib in self.lib_lmds:
            self._compute_second_order_matches(lib)
        self._compute_third_order()

    # Matching

    @staticmethod
    def match_from_filesystem(bin_path, iocg_path):
        l.info("Loading LMD.")
        lmd = LibMatchDescriptor.load_path(bin_path)
        l.info("Loading IOCG.")
        iocg = InterObjectCallgraph.load_path(iocg_path)
        l.info("Computing matches.")
        return LibMatch(lmd, iocg)
