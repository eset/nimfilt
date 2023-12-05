import nimfilt
import ntpath

import idaapi
import ida_dirtree

# Parse all functions in the current IDB for ones that have nim mangled names
def parse_nim_functions():
    seg = idaapi.get_first_seg()
    func = idaapi.get_next_func(seg.start_ea - 1)
    while func is not None:
        name = idaapi.get_func_name(func.start_ea)

        try:
            niname = nimfilt.NimName(name)
            yield start_ea, niname
        except ValueError:
            pass
        func = idaapi.get_next_func(func.start_ea)

# Rename function. Use mangler generated suffix if there is a duplicate
def rename(ea, nname):
    if idaapi.set_name(ea, nname.ida_name):
        return nname.ida_name
    else:
        ida_name = "{}_{}".format(nname.ida_name, nname.suffix)
        idaapi.set_name(ea, ida_name)
        return ida_name

# Packages with an absolute path are locally installed (usually nimble)
# Those with a relative path are either from the stdlib or defined in the current project. TODO: differentiate them
def get_package_types(pkgnames: list):
    absolute = set()
    relative = set()
    for pkg in pkgnames:
        if ntpath.isabs(pkg):
            absolute.add(pkg)
        else:
            relative.add(pkgname)
    return relative, absolute

# TODO: create separate root level directories for Stdlib, project and nimble packages
# TODO: Remove superfluous directory levels
func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
for ea, nname in parse_nim_functions():
    func_dir.mkdir
    ida_name = rename(ea, nname)
    func_dir.mkdir(nname.pkgname)
    func_dir.rename(ida_name, "{}/{}".format(nname.pkgname, ida_name))
