import nimfilt
import posixpath

import idaapi
import ida_dirtree
import ida_name

# Parse all functions in the current IDB for ones that have nim mangled names
def parse_nim_functions():
    seg = idaapi.get_first_seg()
    func = idaapi.get_next_func(seg.start_ea - 1)
    while func is not None:
        name = idaapi.get_func_name(func.start_ea)

        try:
            niname = nimfilt.NimNameCreator(name)
            yield func.start_ea, niname
        except ValueError:
            pass
        func = idaapi.get_next_func(func.start_ea)

# Rename function. Use mangler generated suffix if there is a duplicate
def rename(ea, nname: nimfilt.NimName):
    name = nname.get_ida_name()
    if ida_name.get_name_ea(0, name) != idaapi.BADADDR:
        name = nname.get_ida_name(suffix=nimfilt.SUF_NIM)
        if ida_name.get_name_ea(0, name) != idaapi.BADADDR:
            name = nname.get_ida_name(suffix=nimfilt.SUF_NIM | nimfilt.SUF_IDA)
    idaapi.set_name(ea, name)
    return name

# Recursively merge directories that only have a single child that's also a directory
def merge_dir(dirtree: ida_dirtree.dirtree_t, path=""):
    iterator = ida_dirtree.dirtree_iterator_t()
    ok = dirtree.findfirst(iterator, "{}/*".format(path))
    has_fn = False

    # Moving and deleting directories messes with the iterator so we list all the children first
    children = []
    while ok:
        child_path = dirtree.get_abspath(iterator.cursor)
        children.append(child_path)
        ok = dirtree.findnext(iterator)

    new_children = []
    for child_path in children:
        if dirtree.isdir(child_path):
            child_path = merge_dir(dirtree, child_path)
        else:
            has_fn = True
        new_children.append(child_path)
    if len(children) == 1 and not has_fn:
        # Ida uses POSIX-like path so we use the \\ as an internal separator in directory names
        new_path = "{}\\{}".format(path, posixpath.basename(child_path))
        dirtree.rename(child_path, new_path)
        dirtree.rmdir(path)
        return new_path
    return path

# TODO: create separate root level directories for Stdlib, project and nimble packages
# Rename functions and move them to subdirectories based on the package path/name
func_dirtree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
for ea, nname in parse_nim_functions():
    name = rename(ea, nname)
    func_dirtree.mkdir(nname.pkgname)
    func_dirtree.rename(name, "{}/{}".format(nname.pkgname, name))

merge_dir(func_dirtree)
