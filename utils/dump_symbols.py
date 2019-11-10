import yaml
from bdsig.lmd import LibMatchDescriptor
import sys
import angr

fname = sys.argv[1]
outname = sys.argv[2]

p = angr.Project(fname)
info = {}
info['architecture'] = p.arch.name
info['entry_point'] = p.entry
info['base_address'] = p.loader.min_addr
lmd = LibMatchDescriptor(p)
syms = {s.rebased_addr:s.name for s in lmd.viable_symbols}
info['symbols'] = syms
with open(outname, 'w') as f:
    yaml.dump(info, f)
