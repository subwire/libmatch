import cle
import logging
import pickle
import os
import angr
from angr.errors import SimEngineError, SimMemoryError
from pyvex.lifting.gym.arm_spotter import *
from .iocg import InterObjectCallgraph


l = logging.getLogger("bdsig.lmd")
l.setLevel("DEBUG")


class NormalizedBlock(object):
    # block may span multiple calls
    def __init__(self, project, block, function):
        addresses = [block.addr]
        if block.addr in function.merged_blocks:
            for a in function.merged_blocks[block.addr]:
                addresses.append(a.addr)

        # Before we even start, re-lift the block to unoptimize it
        block = project.factory.block(block.addr, opt_level=0, size=block.size)
        self.addr = block.addr
        self.addresses = addresses
        self.statements = []
        self.all_constants = []
        self.operations = []
        self.call_targets = []
        self.blocks = []
        self.instruction_addrs = []

        if block.addr in function.call_sites:
            targets = function.call_sites[block.addr]
            for blk, target in self.call_targets:
                if project.loader.extern_object.contains_addr(target):
                    target = project.laoder.find_symbol(target).name
                self.call_targets.append((blk, target))
        self.jumpkind = None

        for a in addresses:
            block = project.factory.block(a, opt_level=-1)
            # Ugh, VEX, seriously, not cool. (Fix weird issue with Thumb by supplying size)
            block = project.factory.block(a, opt_level=-1, size=block.size)
            self.instruction_addrs += block.instruction_addrs
            irsb = block.vex
            block._project = None
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
        self.addr = self.orig_function.addr
        # find nodes which end in call and combine them
        done = False
        while not done:
            done = True
            for node in self.graph.nodes():
                try:
                    bl = project.factory.block(node.addr, opt_level=-1)
                except (SimMemoryError, SimEngineError):
                    continue

                """
                successors = list(self.graph.successors(node))
                if bl.vex.jumpkind == 'Ijk_Call' and len(successors) == 0:
                    # Calling a noreturn.  Try to make an edge around it.
                    # Is this in the middle of a function?
                    if (bl.addr + bl.size) < (function.addr + function.size):
                        newblock = None
                        newblock_addr = bl.addr + bl.size
                        newblock_size = None
                        if newblock_addr not in function.graph.nodes:
                            # Find teh size of the block.
                            for a in sorted(list(function.block_addrs)):
                                if a > newblock_addr:
                                    newblock_size = a - newblock_addr
                                    break

                            try:
                                l.debug("Lifting noreturn tail at %#08x size %d" % (newblock_addr, newblock_size))
                                newblock = project.factory.block(newblock_addr, opt_level=-1, size=newblock_size)
                            except (SimMemoryError, SimEngineError):
                                pass
                            if newblock:
                                newnode = newblock.codenode
                                self.graph.add_node(newnode)
                                self.graph.add_edge(node, newnode)
                
                """
                successors = list(self.graph.successors(node))
                # merge if it ends with a single call, and the successor has only one predecessor and succ is after
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
            merged_block = None
            for mb in self.merged_blocks:
                if n.addr == mb.addr:
                    merged_block = mb
                    break

            if n.addr in self.orig_function.get_call_sites():
                call_targets.append(self.orig_function.get_call_target(n.addr))
            if merged_block:
                for block in self.merged_blocks[merged_block]:
                    if block.addr in self.orig_function.get_call_sites():
                        call_targets.append(self.orig_function.get_call_target(block.addr))
            if self.orig_function.endpoints_with_type['transition']:
                for tt in self.orig_function.endpoints_with_type['transition']:
                    if tt.addr == n.addr:
                        call_targets.append(tt.successors()[0].addr)
            if len(call_targets) > 0:
                self.call_sites[n] = call_targets

    def __getattr__(self, a):
        if a == "__getstate__" or a == "__setstate__": # to ensure correct pickling
            raise AttributeError
        if "orig_function" in self.__dict__:
            return getattr(self.orig_function, a)
        else:
            raise AttributeError(a)


class CleLoaderHusk(object):
    """
    A husk of a typical cle Loader, saving only main_object
    """
    def __init__(self, loader):
        self.main_object = CleBackendHusk(loader.main_object)
        self.extern_object = CleBackendHusk(loader.extern_object)
        self.min_addr = loader.min_addr
        self.max_addr = loader.max_addr

class CleBackendHusk(object):
    """
    A husk of a typical cle Backend, saving only .segments, .sections, .symbols, and .plt.
    Supports .contains_addr.
    """
    def __init__(self, backend):
        self.sections = backend.sections
        self.segments = backend.segments
        try:
            self.plt = backend.plt
        except:
            self.plt = None # Blobs do not have a plt
        self.sections_map = backend.sections_map
        self.arch = backend.arch
        self.provides = backend.provides
        try:
            self.all_symbols = backend.all_symbols
        except:
            self.all_symbols = {}
        self.mapped_base = backend.mapped_base

        self.symbols = backend.symbols
        for sym in self.symbols:
            sym.owner = self

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


class LibMatchDescriptor(object):
    """
    A class to precompute all information for a project necessary for LibMatch to run.
    Serializes easily into a (relatively) small blob.
    """
    def __init__(self, proj, banned_names=("$d", "$t")):
        self.cfg = proj.analyses.CFGFast(force_complete_scan=False, 
                resolve_indirect_jumps=True, 
                normalize=True,
                cross_references=True,
                detect_tail_calls=True)
        self.callgraph = self.cfg.kb.callgraph
        self._sim_procedures = {addr: (sp.library_name or "_UNKNOWN_LIB") + ":" + sp.display_name
                                for addr, sp in proj._sim_procedures.items()}

        self.banned_addrs = set()
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

        for norm_f in self.normalized_functions.values():
            for b in norm_f.graph.nodes():
                ord_succ = self._get_ordered_successors(proj, b, norm_f.graph.successors(b))
                self.ordered_successors[(norm_f.addr, b.addr)] = ord_succ

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
        # aaaand cleanup
        for faddr in self.function_manager:
            f = self.function_manager.function(faddr)
            if f.is_plt or f.is_simprocedure \
                    or not f.name or \
                    f.name in banned_names or \
                    self.is_trivial(proj, f):
                self.banned_addrs.add(faddr)

        self.viable_functions = set(self.function_attributes) - set(self.banned_addrs)

        self.viable_symbols = set()
        for sym in self.loader.main_object.symbols:
            if sym.is_function \
                    and not sym.is_hidden \
                    and not sym.is_weak \
                    and sym.binding != "STB_LOCAL" \
                    and sym.rebased_addr not in self.banned_addrs:
                self.viable_symbols.add(sym)
        proj.loader.close()
        del proj.loader
        
    def is_trivial(self, proj, f):
        """
        Return True is a function is "trivial"
        Right now, this means a ret stub, matching those does us no good
        :param f:
        :return:
        """
        # The function is one block.
        if len(list(f.block_addrs)) == 1:
            b = proj.factory.block(list(f.block_addrs)[0])
            if len(b.instruction_addrs) <= 2:# and b.vex.jumpkind == 'Ijk_Ret':
                # mov r0, #0
                # bx lr
                #.... and similar
                return True
            #if len(b.instruction_addrs) == 1:
            #    # One instruction must be either a jump or a ret.
            #    # Or.... uh.. mangled garbage functions i guess
            #    # Either way, it can't do anything useful.
            #g    return True
        return False


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
            normalized_function = self.normalized_functions[function_addr]
            number_of_basic_blocks = len(normalized_function.graph.nodes())
            #number_of_edges = len(normalized_function.graph.edges())
            number_of_edges = 0
            for u, v in normalized_function.graph.edges():
                d = normalized_function.graph.get_edge_data(u, v)
                if 'type' in d and d['type'] == 'fake_return':
                    continue
                number_of_edges += 1

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
            bl = proj.factory.block(block.addr, opt_level=-1)
            for x in bl.vex.all_constants:
                if x in succ:
                    ordered_succ.append(x)

            # add the rest (sorting might be better than no order)
            for s in sorted(succ - set(ordered_succ), key=lambda x:x.addr):
                ordered_succ.append(s)
            return ordered_succ
        except (SimMemoryError, SimEngineError):
            return sorted(succ, key=lambda x:x.addr)


    def symbol_for_addr(self, addr):
        for s in self.loader.main_object.symbols:
            if s.rebased_addr == addr:
                return s
        # Also check the externs
        for s in self.loader.extern_object.symbols:
            if s.rebased_addr == addr:
                return s

    # Creation and Serialization

    @staticmethod
    def make_signature(filename, **project_kwargs):
        proj = angr.Project(filename, **project_kwargs)
        lmd = LibMatchDescriptor(proj)
        return lmd

    @staticmethod
    def make_signature_dump(filename, **project_kwargs):
        lmd = LibMatchDescriptor.make_signature(filename, **project_kwargs)
        path = os.path.abspath(filename) + ".lmd"
        with open(path, "wb") as f:
            lmd.dump(f)
        return path

    @staticmethod
    def load_path(p):
        with open(p, "rb") as f:
            return LibMatchDescriptor.load(f)

    @staticmethod
    def load(f):
        lmd = pickle.load(f)

        if not isinstance(lmd, LibMatchDescriptor):
            raise ValueError("That's not a LibMatchDescriptor!")
        return lmd

    @staticmethod
    def loads(data):
        lmd = pickle.loads(data)

        if not isinstance(lmd, LibMatchDescriptor):
            raise ValueError("That's not a LibMatchDescriptor!")
        return lmd

    def dump_path(self, p):
        with open(p, "wb") as f:
            self.dump(f)

    def dump(self, f):
        return pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)

    def dumps(self):
        return pickle.dumps(self, pickle.HIGHEST_PROTOCOL)

    # Formatting

    def __repr__(self):
        return "<LibMatchDescriptor for %r>" % self.filename

    def __str__(self):
        # TODO: add better str format?
        return repr(self)
