from bdd import *
import logging
import sys
import angr

logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.INFO)

if not sys.argv[1].endswith(".bdd"):
    l.info("Making project . . .")
    p = angr.Project(sys.argv[1], load_options={"auto_load_libs": False})
    l.info("Making signature . . .")
    bdd = BinDiffDescriptor(p)
else:
    l.warn("Using existing bdd")
    bdd = BinDiffDescriptor.load_path(sys.argv[1])

l.warn("Matching . . .")
results = match_all_signatures(bdd, "./objects/")
results = sorted(results, key=lambda x: x[0])
for rate, matched, fname in reversed(results):
    print "Matched %d (%f%%) functions in %s:" % (len(matched), rate * 100, fname)
    for m in matched:
        print "\t%s" % m
