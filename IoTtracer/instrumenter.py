import angr
import networkx as nx
import random
import struct
import os
import sys
import shutil
import matplotlib.pyplot as plt

# generate superblock dominator augmenting graph (SDAG)
def gen_SDAG(cfag, in_node, out_node):

    rev_cfag = cfag.reverse()
    
    pre_dominating_tree = nx.algorithms.dominance.immediate_dominators(cfag, in_node)
    # print("pre_dominating_tree:\n", pre_dominating_tree)

    post_dominating_tree = nx.algorithms.dominance.immediate_dominators(rev_cfag, out_node)
    # print("post_dominating_tree:\n", post_dominating_tree)

    dominator_G = nx.DiGraph()
    pre_dominating_tree_edges = [(value, key) for key, value in pre_dominating_tree.items() if key!=value]
    dominator_G.add_edges_from(pre_dominating_tree_edges)
    post_dominating_tree_edges = [(value, key) for key, value in post_dominating_tree.items() if key!=value]
    dominator_G.add_edges_from(post_dominating_tree_edges)
    # scc = nx.strongly_connected_components(dominator_G)
    # for i, component in enumerate(scc):
    #     print(i, component)

    dominator_G2 = nx.condensation(dominator_G)
    # print(dominator_G2.nodes.data())
    # print(dominator_G2.graph["mapping"])
    return dominator_G2
    

def insert_probe(target, targetarch, targetend, min_addr, max_addr, probe_addrs):
    if targetarch in ("X86", "AMD64") :
        probe_bytes = b'\xcc'
        bytes_num = 1
    elif targetarch in ("ARMEL", "ARMHF", "ARM") :
        if targetend == 'Iend_LE':
            probe_bytes = struct.pack('<I', 0xe7f001f0)
        else:
            probe_bytes = struct.pack('>I', 0xe7f001f0)
        bytes_num = 4
    elif targetarch == "AARCH64" :
        if targetend == 'Iend_LE':
            probe_bytes = struct.pack('<I', 0xd4200000)
        else:
            probe_bytes = struct.pack('>I', 0xd4200000)
        bytes_num = 4
    elif targetarch in ("MIPS32", "MIPS64") :
        if targetend == 'Iend_LE':
            probe_bytes = struct.pack('<I', 0x0005000d)
        else:
            probe_bytes = struct.pack('>I', 0x0005000d)
        bytes_num = 4
    # print(probe_bytes.hex())

    pached_target = target + '_patched'
    shutil.copy(target, pached_target)

    probe_addrs_final = []
    for x in probe_addrs:
        if targetarch in ("MIPS32", "MIPS64") :
            if (x >= min_addr+0x2500) and (x <= max_addr) and (x%bytes_num == 0):
                probe_addrs_final.append(x-min_addr)
        else:
            if (x >= min_addr) and (x <= max_addr) and (x%bytes_num == 0):
                probe_addrs_final.append(x-min_addr)

    probe_addrs_final = sorted(probe_addrs_final)
    print( [hex(x) for x in probe_addrs_final] )

    probe_info = []
    with open(pached_target, 'rb+') as f:
        for offset in probe_addrs_final:
            f.seek(offset)
            data = f.read(bytes_num)
            d = {"addr": offset,
                 "ins": data}
            probe_info.append(d)
            
            f.seek(offset)
            f.write(probe_bytes)

    # print(probe_info)
    with open('probe_info', 'wb') as f:
        for d in  probe_info:
            f.write(hex(d["addr"]).encode('utf-8') + b': ' + d["ins"] + b'\n')

    print(f"✅ Successfully saved {pached_target} and probe_info")

def draw_callgraph(callgraph):
    print(callgraph)

    def addr_to_name(addr):
        if addr in cfg.functions:
            name = cfg.functions[addr].name
            return f"{name}\n({hex(addr)})"
        return hex(addr)

    labelled_graph = nx.relabel_nodes(callgraph, addr_to_name)

    plt.figure(figsize=(16, 16))
    pos = nx.spring_layout(labelled_graph, k=0.5, iterations=50)
    nx.draw(labelled_graph, pos, with_labels=True, node_size=1500, font_size=8, 
            node_color='lightblue', edge_color='gray')
    plt.savefig("callgraph.png", dpi=200, bbox_inches='tight')
    print("✅ Successfully saved callgraph.png")

def draw_CFG_STG(func):
    output_dir = "cfg_per_function"
    os.makedirs(output_dir, exist_ok=True)

    print('.graph: ', func.graph)  #Control Flow Graph
    print('.transition_graph: ', func.transition_graph)  #State Transition Graph

    subgraph = func.graph
    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(subgraph, k=1.0, iterations=50)

    nx.draw_networkx_nodes(subgraph, pos, node_size=800, node_color='lightblue')
    nx.draw_networkx_edges(subgraph, pos, arrowstyle='->', arrowsize=30)
    nx.draw_networkx_labels(subgraph, pos, 
                            labels={n: f"0x{n.addr:x}" for n in subgraph.nodes()},
                            font_size=8)
    plt.savefig(f"{output_dir}/{func.name}_CFG.png", dpi=200, bbox_inches='tight')
    plt.close()
    print(f"✅ Successfully saved {output_dir}/{func.name}_CFG.png")

    subgraph = func.transition_graph
    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(subgraph, k=1.0, iterations=50)

    nx.draw_networkx_nodes(subgraph, pos, node_size=800, node_color='lightblue')
    nx.draw_networkx_edges(subgraph, pos, arrowstyle='->', arrowsize=30)
    nx.draw_networkx_labels(subgraph, pos, 
                            labels={n: f"0x{n.addr:x}" for n in subgraph.nodes()},
                            font_size=8)
    plt.savefig(f"{output_dir}/{func.name}_STG.png", dpi=200, bbox_inches='tight')
    plt.close()
    print(f"✅ Successfully saved {output_dir}/{func.name}_STG.png")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 instrumenter.py <target>")
        sys.exit(1)

    targetname = sys.argv[1]
    print(f"Doing: {targetname}")

    p = angr.Project(targetname, auto_load_libs=False, except_missing_libs=True, main_opts={'base_addr': 0x0})
    min_addr = p.loader.main_object.min_addr
    max_addr = min_addr + os.path.getsize(targetname)
    targetarch = p.arch.name
    targetend = p.arch.memory_endness
    print(targetarch, targetend)

    for i, seg in enumerate(p.loader.main_object.segments):
        start = seg.vaddr
        end = seg.vaddr + seg.memsize - 1
        print(f"Segment {i}: {hex(start)} - {hex(end)} (size: 0x{seg.memsize:x})")

    cfg = p.analyses.CFGFast()
    callgraph = cfg.kb.callgraph
    # draw_callgraph(callgraph)

    probe_addrs = []
    for func_addr, func in cfg.functions.items() :

        if func.is_simprocedure or func.is_plt or func.is_alignment :  
            continue
        
        print(hex(func_addr), func.name)
        # print(func)
        # draw_CFG_STG(func)

        func_CFG = func.graph
        func_CFAG = func_CFG.copy()

        func_CFAG.add_node('dummy_exit')
        in_node = None
        for node in func_CFG.nodes():
            # print(f"addr: 0x{node.addr:x}")
            # print(f"size: {node.size}")
            if node.addr == func_addr :
                in_node = node
            if func_CFG.out_degree(node) == 0 :
                func_CFAG.add_edge(node, 'dummy_exit')
        
        if in_node == None:
            continue

        func_SDAG = gen_SDAG(func_CFAG, in_node, 'dummy_exit')
        # print(func_SDAG.nodes.data())

        # randomly select one BB from each superblock as the probe
        for superblock in func_SDAG.nodes.data() :
            candidates = superblock[1]['members'] - {'dummy_exit'}
            # print(candidates)
            probe = random.choice(list(candidates))
            # print(hex(probe.addr))
            probe_addrs.append(probe.addr)
        # print('\n')

    # print( [hex(x) for x in probe_addrs] )
    insert_probe(targetname, targetarch, targetend, min_addr, max_addr, probe_addrs)