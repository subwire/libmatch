import logging
import sys
import os
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

iocg_path = sys.argv[1].rstrip(os.path.sep) + ".iocg"
# iocg = bdsig.iocg.InterObjectCallgraph.load_path(iocg_path)

lmd_name = bdsig.lmd.LibMatchDescriptor.make_signature_dump(sys.argv[2])

results = bdsig.utils.match_all_iocgs(lmd_name, iocg_path)

total_we_got_correct = 0
total_with_correct = 0

for lib in results[0]:
    print "%s:" % (lib.filename)
    for obj_func_addr in results[0][lib]:
        obj_symbols = filter(lambda x: x.rebased_addr == obj_func_addr, lib.loader.main_object.all_symbols)
        obj_names = " / ".join(y.name for y in obj_symbols)
        correct = list(bin_sym for obj_sym in obj_symbols for bin_sym in symbols if obj_sym.name == bin_sym.name)
        has_correct = len(correct) > 0
        correct_text = ("(correct: " + correct[0].name + ")") if has_correct else "(FUNC HAS NO CORRECT MATCH IN BINARY)"
        correct_addrs = [bin_sym["st_value"] for bin_sym in correct]
        did_we_get_it_right = any(m in correct_addrs for m in results[0][lib][obj_func_addr])
        if has_correct:
            if did_we_get_it_right:
                total_we_got_correct += 1
                message = "(We got it right!)"
            else:
                message = "(WE GOT IT WRONG! " + ("#" * 100) + ")"
            total_with_correct += 1
        else:
            message = ""
        print "\t" + obj_names, "@", hex(obj_func_addr).rstrip("L"), correct_text, message + ":"
        for match_func_addr in results[0][lib][obj_func_addr]:
            match_names = " / ".join(y.name for y in filter(lambda x: x["st_value"] == match_func_addr, symbols))
            print "\t\t" + match_names, "@", hex(match_func_addr).rstrip("L")

print "Total we got right out of total with a correct match:", total_we_got_correct, "/", total_with_correct
