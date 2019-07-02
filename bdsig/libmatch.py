import logging
from .iocg import InterObjectCallgraph
from .lmd import LibMatchDescriptor
from .functiondiff import FunctionDiff
from collections import defaultdict

l = logging.getLogger("bdsig.libmatch")
l.setLevel("DEBUG")

class LibMatch(object):
    def __init__(self, binary_lmd, lmdb):
        """
        :param binary_lmd: The LibMatchDescriptor of the target binary
        :param lib_lmds: An iterable of LibMatchDescriptors corresponding to libraries
        """
        self.binary_lmd = binary_lmd
        self.lmdb = lmdb
        self.ambiguous_funcs = []
        self._first_order_matches = defaultdict()
        self._second_order_matches = defaultdict()

        self._compute()

    @classmethod
    def _first_order_heuristic(self, lib_attrs, bin_attrs):
        """
        The heuristic to use to determine whether or not a given tuple of attrs from a lib func
        should match with a given tuple of attrs from a bin func.
        """
        # TODO: perfect matching
        return lib_attrs == bin_attrs

    def _compute_first_order_matches(self, lib_name, lib_lmds):
        """
        Find matches between a lib and the target binary based purely on function attribute tuples.
        """
        self._first_order_matches[lib_name] = {}
        for lmd in lib_lmds:
            self._first_order_matches[lib_name][lmd] = {}

            for faddr in lmd.viable_functions:
                # match the lib func against the binary if the first order heuristic passes
                attrs = lmd.function_attributes[faddr]
                results = set()
                #results = {bin_faddr for bin_faddr, bin_attrs in self.binary_lmd.function_attributes.items()
                #           if self._first_order_heuristic(attrs, bin_attrs)}
                for bin_faddr, bin_attrs in self.binary_lmd.function_attributes.items():
                    if faddr == 0x4002bd and bin_faddr == 0x00003D45:
                        import ipdb; ipdb.set_trace()
                    if self._first_order_heuristic(attrs, bin_attrs):
                        results.add(bin_faddr)
                self._first_order_matches[lib_name][lmd][faddr] = results

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

    def _compute_second_order_matches(self, lib_name):
        """
        Refine matches between a lib and the target binary based purely on the FunctionDiff method.
        """
        self._second_order_matches[lib_name] = {}
        for lmd, lmd_matches in self._first_order_matches[lib_name].items():
            self._second_order_matches[lib_name][lmd] = {}
            for faddr, func_matches in lmd_matches.items():
                self._second_order_matches[lib_name][lmd][faddr] = []
                for maddr in func_matches:
                    fd = self._second_order_heuristic(self.binary_lmd, lmd, maddr, faddr)
                    if fd.function_a.name == "tcp_recved" and fd.function_b.name == 'tcp_recved':
                        import ipdb;
                        ipdb.set_trace()
                    if fd.probably_identical:
                        self._second_order_matches[lib_name][lmd][faddr].append((maddr, fd))

    def _postprocess_second_order_matches(self):

        # Gather the matches based on the functions in the original binary:
        matches = defaultdict(list)
        #for lib_res in self._second_order_matches:
        for lib_name, lib_matches in self._second_order_matches.items():
            for obj_lmd, obj_res in lib_matches.items():
                for obj_func_addr, obj_func_matches in obj_res.items():
                    if obj_func_matches:
                        for target_addr, match_info in obj_func_matches:
                            if len(matches[target_addr]) > 0:
                                # A collision! But is it a real one?
                                # Did we match better?
                                prev_lib, prev_lmd, prev_match_info = matches[target_addr][0]
                                if match_info.similarity_score > prev_match_info.similarity_score:
                                    # Better match
                                    matches[target_addr] = [(lib_name, obj_lmd, match_info)]
                                elif match_info.similarity_score == prev_match_info.similarity_score:
                                    matches[target_addr].append((lib_name, obj_lmd, match_info))
                                else:
                                    continue  # Worse match, ignore
                            else:
                                matches[target_addr].append((lib_name, obj_lmd, match_info))
        return matches

    def _compute_third_order(self):
        self._plain_matches = self._postprocess_second_order_matches()
        self._candidate_matches = self._postprocess_second_order_matches()
        for f_addr, matches in self._candidate_matches.items():
            if matches:
                self._narrow_third_order(f_addr, matches)

    def _compute_fourth_order(self):
        self.recursion_list = []
        good_hits = []
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) == 1:
                good_hits.append((f_addr, matches,))
        for f_addr, matches in good_hits:
            self._narrow_fourth_order(f_addr, matches)

    def squish(self, func):
        """
        When resolving collisions, are all the collisions duplicates? If so, we probably don't care, and will handle it in post later
        (but we save the dupes for stats purposes)

        :return:
        """
        matches = self._candidate_matches[func]
        the_name = None
        if not matches:
            return
        for lib, lmd, fd in matches:
            if the_name is None:
                if isinstance(fd, str):
                    the_name = fd
                else:
                    the_name = fd.function_b.name
            if isinstance(fd, str) and the_name == fd:
                continue
            elif the_name == fd.function_b.name:
                continue
            else:
                return
        self._candidate_matches[func] = [matches[0]]

    recursion_list = []

    def _narrow_third_order(self, f_addr, matches, exact_narrowing=False):
        # TODO: FIXME:
        # It's possible that you get a single match, and this match is good, but it's wrong, due to function call targets.
        # Maybe we should check everything, even if it has more than one match.
        # No match is better than one wrong one!
        if f_addr in self.recursion_list:
            l.warning("Oof, recursion to %#08x!" % f_addr)
            return
        self.recursion_list.append(f_addr)
        if len(matches) == 1:
            # Perfect match! cannot refine
            self.recursion_list.remove(f_addr)
            return
        l.info("Analyzing function %#08x" % f_addr)
        # Get the target for each candidate match
        target_func = list(matches)[0][2].function_a
        target_callees = []
        for from_block, callees in target_func.call_sites.items():
            for callee in callees:
                if not self.binary_lmd.loader.main_object.contains_addr(callee):
                    # A jumpout! Fuck.
                    callee_name = "UnresolvableCallTarget"
                    target_callees.append({(callee, callee_name,)})
                elif callee in self.binary_lmd.banned_addrs:
                    callee_name = "Ignored"
                    target_callees.append({(callee, callee_name,)})
                elif callee not in self._candidate_matches or len(self._candidate_matches[callee]) == 0:
                    l.error("Cannot disambiguate function at %#08x, unmatched call to %#08x" % (f_addr, callee))
                    self.ambiguous_funcs.append(f_addr)
                    self.recursion_list.remove(f_addr)
                    return  # We're fucked
                else:
                    callee_matches = self._candidate_matches[callee]
                    if len(callee_matches) > 1:
                        if callee == f_addr:
                            l.warning("Recursion is bad!")
                            continue
                        l.error("Recursively resolving %#08x" % callee)
                        self._narrow_third_order(callee, callee_matches)
                        self.squish(callee)

                        if exact_narrowing and len(self._candidate_matches[callee]) > 1:
                            l.error("Failed to narrow down call to %#08x" % callee)
                            self.ambiguous_funcs.append(f_addr)
                            self.recursion_list.remove(f_addr)
                            return
                    possible_callees = set  ()
                    for cm in callee_matches:
                        m_lib, m_lmd, m_fd = cm
                        callee_sym = m_lmd.symbol_for_addr(m_fd.function_b.addr)
                        if not callee_sym:
                            continue
                        callee_name = callee_sym.name
                        possible_callees.add((callee, callee_name,))
                    target_callees.append(possible_callees)
        if not target_callees:
            l.error("No calls in function %#08x, cannot disambiguate" % f_addr)
            self.ambiguous_funcs.append(f_addr)
            return
        # For each possible match
        self._candidate_matches[f_addr] = []
        l.debug("Resolving Function %#08x" % f_addr)
        for lib_name, match_lmd, match_diff in matches:
            match_name = match_diff.function_b.name
            # Get the addresses of each function that library calls.
            lib_callees = []
            for lol in match_diff.function_b.call_sites.values():
                for lmao in lol:
                    lib_callees.append(lmao)
            # Here, we try to compare the functions we matched via direct block comparison with libraries, based on what we think
            # the target actually called.
            # However, we may not be able to accurately resolve the target's callees, so we check that, for each candidate
            # library function, its exact callees are in the set of potential callees in the target.
            # If not, we rule it out.
            for possible_targ_callees, lib_callee in zip(target_callees, lib_callees):
                if not possible_targ_callees:
                    continue
                try:
                    targ_callee_addr = list(possible_targ_callees)[0][0]
                    lib_callee_name = match_lmd.symbol_for_addr(lib_callee).name
                except:
                    l.error("Hmm, something is wrong %#08x %#08x %s" % (f_addr, lib_callee, match_lmd.filename))
                    return
                for targ_callee in possible_targ_callees:
                    targ_callee_addr, targ_callee_name = targ_callee
                    if targ_callee_name == "Ignored":
                        l.debug("Ignoring unresolvable call to %#08x" % targ_callee_addr)
                        break
                    if targ_callee_name == lib_callee_name:
                        l.debug("\t\tMatched call to %s" % targ_callee_name)
                        break
                else:
                    l.debug("\tRuling out %s due to mismatched call to %#08x" % (lib_callee_name, targ_callee_addr))
                    break
            else:
                self._candidate_matches[f_addr].append((lib_name, match_lmd, match_diff))
                l.error("Resolved call to %#08x to %s via callgraph" % (f_addr, match_name))
        self.recursion_list.remove(f_addr)

    def _narrow_fourth_order(self, f_addr, matches):
        """
        By now, we've probably matched a bunch of functions.  But we can't get them all.
        This will use those functions we could match to find the ones we can't.
        In contrast to the third phase, which uses callees to find callers, this does the opposite.
        For each function we can precisely match, collect the set of callees, and assign names to them based on the
        symbols in the source library.

        :param f_addr:
        :param matches:
        :return:
        """
        if f_addr in self.recursion_list:
            l.warning("Oof, recursion to %#08x!" % f_addr)
            return
        self.recursion_list.append(f_addr)
        if len(matches) != 1:
            self.recursion_list.remove(f_addr)
            return
        m_lib, m_lmd, m_fd = matches[0]
        if isinstance(m_fd, str):
            # We've already been here
            self.recursion_list.remove(f_addr)
            return
        target_func = m_fd.function_a
        lib_func = m_fd.function_b
        for (targ_block, targ_callees), (lib_block, lib_callees) in zip(target_func.call_sites.items(), lib_func.call_sites.items()):
           for targ_callee, lib_callee in zip(targ_callees, lib_callees):
                if not self.binary_lmd.loader.main_object.contains_addr(targ_callee):
                    # A jumpout! Fuck.
                    continue
                elif targ_callee in self.binary_lmd.banned_addrs:
                    # Junk.
                    continue
                elif targ_callee not in self._candidate_matches or len(self._candidate_matches[targ_callee]) == 0:
                    # Take a wild guess based on context
                    # Assuming the current match is correct, figure out what it would call in the original
                    # library and make that the name to match.
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if guessed_sym is None:
                        l.info("No findable name for call to %#08x from %#08x(%s)"% (targ_callee, target_func.addr, lib_func.name))
                    else:
                        guessed_name = guessed_sym.name
                        l.info("Guessing name of %#08x is %s due to call from %#08x(%s)" % (targ_callee, guessed_name, target_func.addr, lib_func.name))
                        self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                elif len(self._candidate_matches[targ_callee]) == 1:
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if guessed_sym is None:
                        l.info("No findable name for call to %#08x from %#08x(%s)" % (
                        targ_callee, target_func.addr, lib_func.name))
                    else:
                        guessed_name = guessed_sym.name
                        lol, blah, fd = self._candidate_matches[targ_callee][0]
                        if isinstance(fd, str):
                            if fd == guessed_name:
                                continue
                        else:
                            if fd.function_b.name == guessed_name:
                                continue
                        l.info("Guessing name of %#08x is %s due to call from %#08x(%s)" % (
                        targ_callee, guessed_name, target_func.addr, lib_func.name))
                        self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                    # Nothing to do
                    continue
                else:
                    # We have a collision.  Resolve it by picking the one with the matching
                    # name based on the lib's symbols
                    guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                    if not guessed_sym:
                        l.warning("Couldn't figure out what %#08x is, called by func %#08x" % (lib_callee, lib_func.addr))
                        continue
                    guessed_name = guessed_sym.name
                    new_matches = []
                    for match in self._candidate_matches[targ_callee]:
                        c_lib, c_lmd, c_fd = match
                        if c_fd.function_b.name == guessed_name:
                            l.info("Resolving %#08x to %s via call from %#08x(%s)" % (targ_callee, guessed_name, target_func.addr, lib_func.name))
                            new_matches.append((c_lib, c_lmd, c_fd,))
                    self._candidate_matches[targ_callee] = new_matches
                    if not new_matches:
                        # Welp, it really wasn't the other ones.
                        # Try something new instead
                        guessed_sym = m_lmd.symbol_for_addr(lib_callee)
                        if guessed_sym is None:
                            l.info("No findable name for call to %#08x from %#08x(%s)" % (
                                targ_callee, target_func.addr, lib_func.name))
                        else:
                            guessed_name = guessed_sym.name
                            l.info("Guessing name of %#08x is %s due to call from %#08x(%s)" % (
                                    targ_callee, guessed_name, target_func.addr, lib_func.name))
                            self._candidate_matches[targ_callee] = [(m_lib, m_lmd, guessed_name)]
                    self.squish(targ_callee)
                    if len(self._candidate_matches[targ_callee]) == 1:
                        # Recurse, see if that helps any.
                        l.info("Recursively resolving %#08x" % targ_callee)
                        self._narrow_fourth_order(targ_callee, self._candidate_matches[targ_callee])
        self.recursion_list.remove(f_addr)

    def _dedup(self):
        """
        During all the previous phases, we'll make guesses, and all sorts of cool stuff.
        Now we have a bit of cleanup to do.  If we guessed a name for a function x, and a collision for
        function y includes the name of x, take it out of y's list, as we assume we can only have one copy of x in the binary
        THis means, by process of elimination, we may get even more matches!
        :return:
        """
        import copy
        good_hits = []
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) == 1:
                m_lib, m_lmd, m_fd = matches[0]
                if isinstance(m_fd, str):
                    # A guess has no fd
                    good_hits.append(m_fd)
                else:
                    good_hits.append(m_fd.function_b.name)
        for f_addr, matches in self._candidate_matches.items():
            if len(matches) > 1:
                fixed_matches = copy.copy(matches)
                for match in matches:
                    m_lib, m_lmd, m_fd = match
                    if m_fd.function_b.name in good_hits:
                        l.info("Removing %s from consideration for %#08x" % (m_fd.function_b.name, f_addr))
                        fixed_matches.remove(match)
                self._candidate_matches[f_addr] = fixed_matches

    def _compute(self):
        """
        Compute everything, hopefully resulting in matches!
        """
        # first, find all first order matches (matches depending only on the attr tuples)
        l.info("Phase 1: Coarse statistical matching")
        for lib, lib_lmds in self.lmdb.lib_lmds.items():
            self._compute_first_order_matches(lib, lib_lmds)
        l.info("Phase 2: FunctionDiff")
        for lib in self.lmdb.lib_lmds:
            self._compute_second_order_matches(lib)
        l.info("Phase 3: Callee context")
        self._compute_third_order()
        l.info("Phase 4: Caller context")
        self._compute_fourth_order()
        l.info("Phase 5: Cleanup")
        self._dedup()
