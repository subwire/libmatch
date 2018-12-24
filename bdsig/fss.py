import angr
from angr.analyses.cfg import CFGFast
from networkx.classes import DiGraph
from angr.knowledge_plugins.functions import Function


def tg_to_fss(f: Function, cfg: CFGFast):
    """
    Convert a function to FunctionSimSearch's
    CFG format.
    :param f:
    :param cfg:
    :return:
    """
    fg = f.transition_graph
    disasm = cfg.project.analyses.Disassembly(f)
    fss = dict()
    fss['edges'] = list()
    fss['nodes'] = list()

    # Convert edges
    for edg in fg.edges:
        src, dst = edg
        fss_edge = {'source': src.addr, 'destination': dst.addr}
        fss['edges'].append(fss_edge)

    for n in fg.nodes:
        fss_node = {'address': n.addr}
        fss_node['instructions'] = list()
        for iaddr in disasm.block_to_insn_addrs[n.addr]:
            i = disasm.raw_result_map['instructions'][iaddr]
            fss_ins = dict()
            fss_ins['mnemonic'] = i.mnemonic.opcode_string
            fss_ins['operands'] = [o.render() for o in i.operands]
            fss_node['instructions'].append(fss_ins)
        fss['nodes'].append(fss_node)
    return fss


