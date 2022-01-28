import angr

# name = 'SDMMC_CmdGoIdleState'
name = 'SD_initialize'
firmware = "firmware/sdio-demo.elf"

proj = angr.Project(firmware)
function = proj.loader.main_object.get_symbol(name)
start_state = proj.factory.blank_state(addr=function.rebased_addr)
cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[function.rebased_addr], initial_state=start_state)
# plot_cfg(cfg, f"{name}_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)

entry = cfg.model.get_any_node(function.rebased_addr)

paths = []

def dfs(node, stack=[]):
    print(node)
    if node in stack:
        return
    
    stack.append(node)
    if len(cfg.graph.adj[node]) == 0:
        paths.append([node for node in stack])
        print(len(path))

    for here, adj in cfg.graph.edges([node]):
        attr = cfg.graph.edges()[(here, adj)]
        if attr['jumpkind'] != 'Ijk_FakeRet':
            dfs(adj, stack)

    stack.pop(-1)

print('Start exploring')
dfs(entry)
# print(len(list(cfg.graph.edge())))
# print(len(paths))