import networkx
import logging
import pickle


l = logging.getLogger("bdsig.iocg")
l.setLevel("DEBUG")

class NameCollisionException(Exception):
    pass


class InterObjectCallgraph(object):
    """
    A class to handle the creation of a callgraph between all libs.
    The callgraph is implemented as a networkx.DiGraph.
    """
    def __init__(self, lib_lmds):
        self.lib_lmds = lib_lmds
        self.callgraph = None
        self.named_funcs = None
        self.all_funcs = None
        self._gen_global_maps()
        self._compute_graph()

    def _gen_global_maps(self):
        """
        Merge all of the named functions into one space while checking for duplicate symbols.
        self._functions_by_symbols is ELFSymbol -> (NormalizedFunction, LibMatchDescriptor)
        self._all_funcs is NormalizedFunction -> LibMatchDescriptor
        """
        self._functions_by_symbol = {}

        # first, add all named_funcs and check for collisions in naming
        for lib in self.lib_lmds:
            for sym in lib.viable_symbols:
                if not sym.rebased_addr in lib.normalized_functions:
                    l.warn("Symbol '%s' at %#x not in normalized_functions for lib %s; skipping symbol."
                           % (sym.name, sym.rebased_addr, lib.filename))
                    continue
                f = lib.normalized_functions[sym.rebased_addr]
                if not sym.is_weak:
                    if self.lookup_by_name(sym.name):
                        raise NameCollisionException(f.name + " " + lib.filename)
                    self._functions_by_symbol[sym] = (f, lib)

        # next, add all remaining funcs
        self._all_funcs = {f: l for f, l in self._functions_by_symbol.values()}
        for lib in self.lib_lmds:
            for faddr in lib.function_manager:
                f = lib.normalized_functions[faddr]
                self._all_funcs[f] = lib

    def lookup_by_name(self, name):
        """
        Look up a *named* (i.e. by a symbol) function by name.
        """
        for sym in self._functions_by_symbol:
            if sym.name == name:
                return self._functions_by_symbol[sym]
        return None

    def _compute_graph(self):
        """
        Compute the callgraph. Inter-object references are resolved by chepcking if the destination
        func is a simproc or plt entry and, if so, looking up the name in the function symbol list.
        Result is placed in self.callgraph.
        """
        self.callgraph = networkx.DiGraph()
        self.callgraph.add_nodes_from(self._all_funcs)
        for f, lib in self._all_funcs.items():
            for succ_addr in lib.callgraph[f.addr]:
                succ = lib.normalized_functions[succ_addr]
                if not (succ.is_simprocedure or succ.is_plt):
                    self.callgraph.add_edge(f, succ)
                else:
                    match = self.lookup_by_name(succ.name)
                    if match:
                        self.callgraph.add_edge(f, match[0])  # get the func out of the (func, lib) tuple
                    else:
                        l.debug("Ignoring %s in %s" % (succ.name, lib.filename))

    # Creation and Serialization

    @staticmethod
    def load_path(p):
        with open(p, "rb") as f:
            return InterObjectCallgraph.load(f)

    @staticmethod
    def load(f):
        lmd = pickle.load(f)

        if not isinstance(lmd, InterObjectCallgraph):
            raise ValueError("That's not a InterObjectCallgraph!")
        return lmd

    @staticmethod
    def loads(data):
        lmd = pickle.loads(data)

        if not isinstance(lmd, InterObjectCallgraph):
            raise ValueError("That's not a InterObjectCallgraph!")
        return lmd

    def dump_path(self, p):
        with open(p, "wb") as f:
            self.dump(f)

    def dump(self, f):
        return pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)

    def dumps(self):
        return pickle.dumps(self, pickle.HIGHEST_PROTOCOL)
