import logging
import sys
import bdsig

logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.ERROR)

bdsig.utils.make_all_signatures(sys.argv[1])
