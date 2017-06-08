from bd_signature import *
import logging
import sys

logging.basicConfig()
l = logging.getLogger()
l.setLevel(logging.ERROR)

make_all_signatures(sys.argv[1])
