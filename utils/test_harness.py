import logging
import sys
import bdsig
import elftools


logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.ERROR)

bdsig.utils.make_iocg(sys.argv[1])

with open(sys.argv[2], "rb") as f:
    elf = elftools.elf.elffile.ELFFile(f)

    sym_sec = elf.get_section_by_name(".symtab")
    symbols = list(sym_sec.iter_symbols())

#import ipdb; ipdb.set_trace()

lmd_name = bdsig.lmd.LibMatchDescriptor.make_signature_dump(sys.argv[2])

results = bdsig.utils.match_all_iocgs(lmd_name, sys.argv[1])

print results
