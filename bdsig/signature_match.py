from bd_signature import *
import logging
import sys
import angr

logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.ERROR)

p = angr.Project(sys.argv[1])
cfg = p.analyses.CFGFast()

results = match_all_signatures(p, cfg, "./objects/")
results = sorted(results,key=lambda x: x[2])
for matched, unmatched, rate, sig in reversed(results):
	print "Matched %d (%f%%) functions in %s:" % (len(matched), rate, sig.name)
	for addr_a, addr_b, sym in matched:
		print "\tFound %s at %s" % (sym.name, hex(addr_b))
