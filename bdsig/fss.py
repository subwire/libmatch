import angr
from angr.analyses.cfg import CFGFast
from networkx.classes import DiGraph
from angr.knowledge_plugins.functions import Function
import functionsimsearch
from angr.analyses import Analysis, register_analysis

def tg_to_fss(f: Function, cfg: CFGFast):
    """
    Convert a function to FunctionSimSearch's
    CFG format.
    :param f:
    :param cfg:
    :return:
    """
    fgwi = functionsimsearch.FlowgraphWithInstructions()
    fg = f.transition_graph
    disasm = cfg.project.analyses.Disassembly(f)
    fss = dict()
    fss['edges'] = list()
    fss['nodes'] = list()

    # Convert edges
    for edg in fg.edges:
        src, dst = edg
        fgwi.add_edge(src.addr, dst.addr)

    for n in fg.nodes:
        fgwi.add_node(n.addr)
        inss = list()
        for iaddr in disasm.block_to_insn_addrs[n.addr]:
            i = disasm.raw_result_map['instructions'][iaddr]
            mnem = i.mnemonic.opcode_string
            ops = tuple([o.render()[0].strip("{}\[\]") for o in i.operands])
            inss.append((mnem, ops))
        inss = tuple(inss)
        fgwi.add_instructions(n.addr, inss)
    return fgwi



class SimSimSearch(Analysis):
    pass
