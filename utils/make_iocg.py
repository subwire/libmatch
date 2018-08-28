import logging
import sys
import bdsig

logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.ERROR)

bdsig.utils.make_iocg(sys.argv[1])
