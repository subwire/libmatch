import angr
from bdsig.utils import *
import struct
import sys
# Mini blob loader for CM3 blob images.

blob_fn = sys.argv[1]
libs_dir = sys.argv[2]
with open(blob_fn, 'rb') as f:
    initial_sp = struct.unpack('<I', f.read(4))[0]
    entry = struct.unpack('<I', f.read(4))[0]
    base = entry & 0xffff0000 # wow that's gross

# do it
p = angr.Project(blob_fn,
                 main_opts={'custom_base_addr': base,
                            'custom_arch': 'ARMEL',
                            'backend': 'blob',
                            'custom_entry_point': entry,
                            'force_rebase': True})
import IPython; IPython.embed()
collect_best_matches_for_library(p, sys.argv[2])
