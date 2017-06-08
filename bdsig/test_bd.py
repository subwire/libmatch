import angr 
import sys

p = angr.Project(sys.argv[1])
p2 = angr.Project(sys.argv[2])
cfg1 = p.analyses.CFGFast()
cfg2 = p2.analyses.CFGFast()
bd = angr.analyses.BinDiff(p2, cfg_a=cfg1, cfg_b=cfg2)
