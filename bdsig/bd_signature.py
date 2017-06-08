import angr
import copy
import pickle
import os
import logging

logger = logging.getLogger("BDSignature")

class BDSignature:

    def i__init__(self, project, cfg=None, project_kwargs=None):
        """
        Create a "signature" out of this project.
        :param project:
        """
        self.symbols = project.loader.main_bin.symbols_by_addr
        if not cfg:
            self.cfg = project.analyses.CFGFast()
        else:
            self.cfg = cfg
        self.callgraph = self.cfg.kb.callgraph
        self.functions = self.cfg.kb.functions
        self.project = project
        self.project_kwargs = project_kwargs
        if project.loader.main_bin.provides:
            self.name = project.loader.main_bin.provides
        else:
            self.name = os.path.basename(project.filename)

    @staticmethod
    def load(filename):
        if not filename.endswith(".bdsig"):
            raise ValueError("You probably want a bdsig file here")
        origfile = filename.rstrip('.bdsig')
        if not os.path.exists(origfile):
            raise ValueError("Could not find the file " + origfile + ". This is needed to load bdsigs currently")
        with open(filename, 'rb') as f:
            thing = pickle.load(f)
        thing.project = angr.Project(origfile)
        try:
            thing.project.kb.callgraph = thing.callgraph
        except AttributeError:
            # Already got it
            pass
        try:
            thing.project.kb.functions = thing.functions
        except:
            pass
        # Dammit salls....
        thing.cfg.kb = thing.project.kb
        return thing

    @staticmethod
    def loads(stream, origstream):
        thing = pickle.loads(stream)
        thing.project = angr.Project(origstream)
        try:        
            thing.project.kb.callgraph = thing.callgraph
            except AttributeError:
                # Already got it
                pass    
            try:        
                thing.project.kb.functions = thing.functions
            except:     
                pass    
            # Dammit salls....
            thing.cfg.kb = thing.project.kb
            return thing
                                                                                                                
    def dump(self):
        outfn = self.project.filename + ".bdsig"
        thing = copy.deepcopy(self)
        thing.project = None
        with open(outfn, 'wb') as f:
            pickle.dump(thing, f)

    def dumps(self):
        thing = copy.deepcopy(self)
        thing.project = None
        return pickle.dumps(thing)


    def match(self, thing, cfg, match_all_funcs=False):
        """

        :param thing:
        :param cfg:
        :param match_all_funcs:
        :return: Matched functions, unmatched functions, and the match rate
        """
        bd = thing.analyses.BinDiff(self.project, cfg_a=cfg, cfg_b=self.cfg)
        # Flip our matches around, get a dict of stuff in the library to stuff in the bin
        matches = dict([tuple(reversed(tuple(x))) for x in bd.function_matches])
        matched = []
        unmatched = []
        if match_all_funcs:
            syms = self.project.kb.functions
        else:
            syms = self.project.loader.main_bin.symbols_by_addr
        assert len(syms) > 0
        for addr, sym in syms.items():
            # EDG says: .....
            addr = sym.rebased_addr
            if addr in matches:
                matched.append((addr, matches[addr], sym))
            else:
                unmatched.append((addr, sym))
        return matched, unmatched, (float(len(matched)) / float(len(syms)))

    @staticmethod
    def make_signature(filename, project_kwargs=None):
        proj = angr.Project(filename, project_kwargs)
        sig = BDSignature(proj,project_kwargs=project_kwargs)
        sig.dump()

class BDArchiveSignature:

    def __init__(self, filename):
        # Attempt to open it
        archive = arpy.Archive(filename)
        archive.read_all_headers()
        self.name = os.path.basename(filename) # TODO: this is gross
        logger.debug("Loaded archive for filename")
        # TODO: Archive some metadata here!
        self.files = {}
        for fname, arfile in archive.archived_files.items():
            self.files[fname] = None
            try:
                logger.debug("Processing %s:%s" % (filename, fname))
                proj = angr.Project(arfile)
                cfg = proj.analyses.CFGFast()
                self.files[fname] = BDSignature(proj, cfg)
    
    def dump(self, fname):
        thing = copy.deepcopy(self)
        thing.files = {fn:sig.dumps() for fn, sig in thing.files.items()}
        with open(fname, 'wb') as f:
            pickle.dump(thing, f)
    
    @staticmethod
    def load(fname):
        if not fname.endswith(".bdasig"):
            raise ValueError("You probably want a .bdasig file here")
        origfn = fname.rstrip(".bdasig")
        if not os.path.exists(origfn):
            raise ValueError("Can't find the original file for bdasig " + origfn)
        with open(fname, 'rb') as f:
            with arpy.open(origfn) as arf:
                thing = pickle.load(f)
                thing.files = {fn:fn.loads(sig, arf.archived_files[fn]) for fn, sig in thing.files}

    @staticmethod
    def make_signature(fname):
        outfn = fname + ".bdasig"

def make_all_signatures(rootDir):
    for dirName, subdirList, fileList in os.walk(rootDir):
        logger.debug('Found directory: %s' % dirName)
        for fname in fileList:
            if fname.endswith(".o"):
                fullfname = os.path.join(dirName, fname)
                logger.debug("Making signature for " + fullfname)
                try:
                    BDSignature.make_signature(fullfname)
                except Exception as e:
                    logger.exception("Could not make signature for " + fullfname)


def match_all_signatures(project, cfg, rootDir):
    candidates = []
    for dirName, subdirList, fileList in os.walk(rootDir):
        logger.debug('Found directory: %s' % dirName)
        for fname in fileList:
            if fname.endswith(".bdsig"):
                fullfname = os.path.join(dirName, fname)
                logger.debug("Checking signature for " + fullfname)
                try:
                    sig = BDSignature.load(fullfname)
                    m, u, r = sig.match(project, cfg)
                    if r > 0.0:
                        candidates.append((m,u,r,sig))
                    else:
                        del sig
                except Exception as e:
                    logger.exception("Could not make signature for " + fullfname)
    return candidates
