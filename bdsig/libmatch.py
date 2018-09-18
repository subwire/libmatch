import logging
from .iocg import InterObjectCallgraph
from .lmd import LibMatchDescriptor
from .functiondiff import FunctionDiff


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

    def _compute(self):
        """
        Compute everything, hopefully resulting in matches!
        """
        # first, find all first order matches (matches depending only on the attr tuples)
        for lib in self.lib_lmds:
            self._compute_first_order_matches(lib)

        for lib in self.lib_lmds:
            self._compute_second_order_matches(lib)


    # Matching

    @staticmethod
    def match_from_filesystem(bin_path, iocg_path):
        l.info("Loading LMD.")
        lmd = LibMatchDescriptor.load_path(bin_path)
        l.info("Loading IOCG.")
        iocg = InterObjectCallgraph.load_path(iocg_path)
        l.info("Computing matches.")
        return LibMatch(lmd, iocg)
