import bdsig
import logging
import sys
import angr

logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.INFO)

# python match_all_iocgs.py lmd_path directory_with_iocgs

if not sys.argv[1].endswith(".lmd"):
    l.warn("Making signature . . .")
    bdsig.lmd.LibMatchDescriptor.make_signature_dump(sys.argv[1])
    sys.argv[1] += ".lmd"
else:
    l.warn("Using existing lmd")

l.info("Matching . . .")
results = bdsig.utils.match_all_iocgs(sys.argv[1], sys.argv[2])

# TODO: update once .result_stats is implemented in match_all_iocgs in utils.py
print "Second order matches:"
print results

"""
results = sorted(results, key=lambda x: x[0])
for rate, matched, fname in reversed(results):
    print "Matched %d (%f%%) functions in %s:" % (len(matched), rate * 100, fname)
    for m in matched:
        print "\t%s" % m
"""
