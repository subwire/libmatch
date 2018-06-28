import cle
import logging
import pickle
import os
import angr
from angr.errors import SimEngineError, SimMemoryError
from fastbindiff import BinDiff


l = logging.getLogger("bdd")
l.setLevel("DEBUG")


class NormalizedBlock(object):
    # block may span multiple calls
    def __init__(self, project, block, function):
        addresses = [block.addr]
        if block.addr in function.merged_blocks:
            for a in function.merged_blocks[block.addr]:
                addresses.append(a.addr)

        self.addr = block.addr
        self.addresses = addresses
        self.statements = []
        self.all_constants = []
        self.operations = []
        self.call_targets = []
        self.blocks = []
        self.instruction_addrs = []

        if block.addr in function.call_sites:
            self.call_targets = function.call_sites[block.addr]

        self.jumpkind = None

        for a in addresses:
            block = project.factory.block(a)
            block._project = None
            self.instruction_addrs += block.instruction_addrs
            irsb = block.vex
            self.blocks.append(block)
            self.statements += irsb.statements
            self.all_constants += irsb.all_constants
            self.operations += irsb.operations
            self.jumpkind = irsb.jumpkind

        self.size = sum([b.size for b in self.blocks])

    def __repr__(self):
        size = sum([b.size for b in self.blocks])
        return '<Normalized Block for %#x, %d bytes>' % (self.addr, size)


class NormalizedFunction(object):
    # a more normalized function
    def __init__(self, project, function):
        # start by copying the graph
        self.graph = function.graph.copy()
        self.call_sites = dict()
        self.startpoint = function.startpoint
        self.merged_blocks = dict()
        self.orig_function = function

        # find nodes which end in call and combine them
        done = False
        while not done:
            done = True
            for node in self.graph.nodes():
                try:
                    bl = project.factory.block(node.addr)
                except (SimMemoryError, SimEngineError):
                    continue

                # merge if it ends with a single call, and the successor has only one predecessor and succ is after
                successors = list(self.graph.successors(node))
                if bl.vex.jumpkind == "Ijk_Call" and len(successors) == 1 and \
                        len(list(self.graph.predecessors(successors[0]))) == 1 and successors[0].addr > node.addr:
                    # add edges to the successors of its successor, and delete the original successors
                    succ = list(self.graph.successors(node))[0]
                    for s in self.graph.successors(succ):
                        self.graph.add_edge(node, s)
                    self.graph.remove_node(succ)
                    done = False

                    # add to merged blocks
                    if node not in self.merged_blocks:
                        self.merged_blocks[node] = []
                    self.merged_blocks[node].append(succ)
                    if succ in self.merged_blocks:
                        self.merged_blocks[node] += self.merged_blocks[succ]
                        del self.merged_blocks[succ]

                    # stop iterating and start over
                    break

        # set up call sites
        for n in self.graph.nodes():
            call_targets = []
            if n.addr in self.orig_function.get_call_sites():
                call_targets.append(self.orig_function.get_call_target(n.addr))
            if n.addr in self.merged_blocks:
                for block in self.merged_blocks[n]:
                    if block.addr in self.orig_function.get_call_sites():
                        call_targets.append(self.orig_function.get_call_target(block.addr))
            if len(call_targets) > 0:
                self.call_sites[n] = call_targets


class CleLoaderHusk(object):
    """
    A husk of a typical cle Loader, saving only main_object
    """
    def __init__(self, loader):
        self.main_object = CleBackendHusk(loader.main_object)


class CleBackendHusk(object):
    """
    A husk of a typical cle Backend, saving only .segments, .sections, .symbols_by_addr, and .plt.
    Supports .contains_addr.
    """
    def __init__(self, backend):
        self.sections = backend.sections
        self.segments = backend.segments
        self.plt = backend.plt
        self.sections_map = backend.sections_map
        self.arch = backend.arch
        self.provides = backend.provides

        self.symbols_by_addr = backend.symbols_by_addr
        for sym in self.symbols_by_addr.itervalues():
            sym.owner_obj = self

    def contains_addr(self, addr):
        """
        Is `addr` in one of the binary's segments/sections we have loaded? (i.e. is it mapped into memory ?)
        """
        return self.find_loadable_containing(addr) is not None

    def find_loadable_containing(self, addr):
        lookup = self.find_segment_containing if self.segments else self.find_section_containing
        return lookup(addr)

    def find_segment_containing(self, addr):
        """
        Returns the segment that contains `addr`, or ``None``.
        """
        return self.segments.find_region_containing(addr)

    def find_section_containing(self, addr):
        """
        Returns the section that contains `addr` or ``None``.
        """
        return self.sections.find_region_containing(addr)


class BinDiffDescriptor(object):
    """
    A class to precompute all information for a project necessary for BinDiff to run.
    Serializes easily into a (relatively) small blob.
    """
    def __init__(self, proj):
        self.cfg = proj.analyses.CFGFast()
        self._sim_procedures = {addr: (sp.library_name or "_UNKNOWN_LIB") + ":" + sp.display_name
                                for addr, sp in proj._sim_procedures.iteritems()}
        self.normalized_functions = {}
        self.normalized_blocks = {}
        self.ordered_successors = {}
        self.filename = proj.filename

        for faddr in self.cfg.kb.functions:
            f = self.cfg.kb.functions.function(faddr)
            self.normalized_functions[f.addr] = NormalizedFunction(proj, f)
            for b in f.graph.nodes():
                try:
                    self.normalized_blocks[(f.addr, b.addr)] = NormalizedBlock(proj, b, self.normalized_functions[f.addr])
                except (SimMemoryError, SimEngineError):
                    self.normalized_blocks[(f.addr, b.addr)] = None

        for norm_f in self.normalized_functions.itervalues():
            for b in norm_f.graph.nodes():
                ord_succ = self._get_ordered_successors(proj, b, norm_f.graph.successors(b))
                self.ordered_successors[(norm_f.orig_function.addr, b.addr)] = ord_succ

        self.function_attributes = self._compute_function_attributes()

        for faddr in self.cfg.kb.functions:
            f = self.cfg.kb.functions.function(faddr)
            f._project = None
            f._block_cache = {}

        self.function_manager = self.cfg.kb.functions.copy()
        self.function_manager._kb = None

        for faddr in self.cfg.kb.functions:
            f = self.cfg.kb.functions.function(faddr)
            f._function_manager = self.function_manager

        # Do this last because it is somewhat dangerous (must modify symbol owner object references)
        self.loader = CleLoaderHusk(proj.loader)

    def is_hooked(self, addr):
        return addr in self._sim_procedures

    def _compute_function_attributes(self):
        """
        :returns:    a dictionary of function addresses to tuples of attributes
        """

        # the attributes we use are the number of basic blocks, number of edges, and number of subfunction calls
        attributes = dict()
        all_funcs = set(self.cfg.kb.callgraph.nodes())
        for function_addr in self.cfg.kb.functions:
            # skip syscalls and functions which are None in the cfg
            if self.cfg.kb.functions.function(function_addr) is None or self.cfg.kb.functions.function(function_addr).is_syscall:
                continue
            if self.cfg.kb.functions.function(function_addr) is not None:
                normalized_function = self.normalized_functions[function_addr]
                number_of_basic_blocks = len(normalized_function.graph.nodes())
                number_of_edges = len(normalized_function.graph.edges())
            else:
                number_of_basic_blocks = 0
                number_of_edges = 0
            if function_addr in all_funcs:
                number_of_subfunction_calls = len(list(self.cfg.kb.callgraph.successors(function_addr)))
            else:
                number_of_subfunction_calls = 0
            attributes[function_addr] = (number_of_basic_blocks, number_of_edges, number_of_subfunction_calls)

        return attributes

    def _get_ordered_successors(self, proj, block, succ):
        try:
            # add them in order of the vex
            succ = set(succ)
            ordered_succ = []
            bl = proj.factory.block(block.addr)
            for x in bl.vex.all_constants:
                if x in succ:
                    ordered_succ.append(x)

            # add the rest (sorting might be better than no order)
            for s in sorted(succ - set(ordered_succ), key=lambda x:x.addr):
                ordered_succ.append(s)
            return ordered_succ
        except (SimMemoryError, SimEngineError):
            return sorted(succ, key=lambda x:x.addr)

    # Creation and Serialization

    @staticmethod
    def make_signature(filename, **project_kwargs):
        proj = angr.Project(filename, **project_kwargs)
        bdd = BinDiffDescriptor(proj)
        with open(os.path.abspath(filename) + ".bdd", "wb") as f:
            bdd.dump(f)

    @staticmethod
    def load_path(p):
        with open(p, "rb") as f:
            return BinDiffDescriptor.load(f)

    @staticmethod
    def load(f):
        bdd = pickle.load(f)

        if not isinstance(bdd, BinDiffDescriptor):
            raise ValueError("That's not a BinDiffDescriptor!")
        return bdd

    @staticmethod
    def loads(data):
        bdd = pickle.loads(data)

        if not isinstance(bdd, BinDiffDescriptor):
            raise ValueError("That's not a BinDiffDescriptor!")
        return bdd

    def dump(self, f):
        return pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)

    def dumps(self):
        return pickle.dumps(self, pickle.HIGHEST_PROTOCOL)

    # Matching

    @staticmethod
    def diff(bdd_a, bdd_b):
        return BinDiff(bdd_a, bdd_b)

    @staticmethod
    def diff_from_filesystem(path_a, path_b):
        with open(path_a, "rb") as f:
            bdd_a = BinDiffDescriptor.load(f)
        with open(path_b, "rb") as f:
            bdd_b = BinDiffDescriptor.load(f)

        return BinDiffDescriptor.diff(bdd_a, bdd_b)


def make_all_signatures(rootDir):
    for dirName, subdirList, fileList in os.walk(rootDir):
        l.debug('Found directory: %s' % dirName)
        for fname in fileList:
            if fname.endswith(".o"):
                fullfname = os.path.join(dirName, fname)
                l.debug("Making signature for " + fullfname)
                try:
                    BinDiffDescriptor.make_signature(fullfname, load_options={"rebase_granularity": 0x1000})
                except angr.errors.AngrCFGError:
                    l.warn("No executable data for %s, skipping" % fullfname)
                except Exception as e:
                    l.exception("Could not make signature for " + fullfname)
            """
            elif fname.endswith('.a'):
                fullfname = os.path.join(dirName, fname)
                l.debug("Making signature for archive " + fullfname)
                BDArchiveSignature.make_signature(fullfname)
            """

def match_all_signatures(bdd, rootDir):
    candidates = []
    for dirName, subdirList, fileList in os.walk(rootDir):
        l.debug('Found directory: %s' % dirName)
        for fname in fileList:
            if fname.endswith(".bdd"):
                fullfname = os.path.join(dirName, fname)
                l.debug("Checking signature for " + fullfname)
                try:
                    sig = BinDiffDescriptor.load_path(fullfname)
                    bd = BinDiffDescriptor.diff(bdd, sig)

                    r, matched = bd.lib_result_stats()
                    if r > 0.0:
                        candidates.append((r, matched, fname))

                except Exception as e:
                    l.exception("Could not make signature for " + fullfname)
    return candidates
