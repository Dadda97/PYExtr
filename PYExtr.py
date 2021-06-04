import ast
import json
import argparse
import os
from os import listdir
from os.path import isfile, join
import python_exe_unpack
import hashlib

class PYExtr(ast.NodeVisitor):
    # Thanks to mortbauer's answer
    # https://stackoverflow.com/a/14661325/11033123
    
    def __init__(self):
        super().__init__()

        self.strings = dict()
        self.functions = dict()
        self.imports = []
        self.current_class="" 


    def recursive(func):
        def wrapper(self,node):
            func(self,node)
            for child in ast.iter_child_nodes(node):
                self.visit(child)
        return wrapper

    @recursive
    def visit_Str(self, node): 
        if node.value in self.strings:
            self.strings[node.value] += 1
        else:
            self.strings[node.value] = 1
    
    def get_node_name(self,node):
        node_name = type(node).__name__
        return [node_name] if "FunctionDef" not in node_name and "ClassDef" not in node_name else []

    def get_all_nodes(self,node):
        child_nodes=  list(ast.iter_child_nodes(node))
        if len(child_nodes) == 0:
            return self.get_node_name(node)
        res = []
        for child_node in child_nodes:
             res +=  self.get_all_nodes(child_node)
        node_name = self.get_node_name(node)
        return node_name + res

    def get_global_nodes(self, node):
        child_nodes=  list(ast.iter_child_nodes(node))
        if len(child_nodes) == 0:
            return self.get_node_name(node)
        res = []
        for child_node in [x for x in child_nodes if len(self.get_node_name(x)) > 0] :
             res +=  self.get_global_nodes(child_node)
        node_name = self.get_node_name(node)
        return node_name + res

    def get_fun_hash(self,node,global_fun = False):
        nodes = self.get_all_nodes(node) if not global_fun else self.get_global_nodes(node)
        return hashlib.sha256(("-".join(nodes).encode("UTF-8"))).hexdigest()
    
    @recursive
    def visit_FunctionDef(self,node):
        if not hasattr(node,"alreadyVisited"):
            self.functions[node.name] = self.get_fun_hash(node)

    @recursive
    def visit_AsyncFunctionDef(self,node):
        if not hasattr(node,"alreadyVisited"):
            self.functions[node.name] = self.get_fun_hash(node)
    
    @recursive
    def visit_Import(self,node):
        for imp in node.names:
            self.imports.append(imp.name)

    @recursive
    def visit_ImportFrom(self,node):
        self.imports.append(node.module)


    @recursive
    def visit_ClassDef(self,node):
        class_name = node.name
        methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
        for method in methods:
            self.functions[class_name + "." + method.name] = self.get_fun_hash(node)
            method.alreadyVisited = True

    @recursive
    def visit_Module(self,node):
        self.functions["+global+"] = self.get_fun_hash(node, global_fun = True)

    @recursive
    def generic_visit(self,node):
        pass


def input_path(string):
    if os.path.isdir(string) or os.path.isfile(string):
        return string
    else:
        raise NameError(f"Cannot open input file: No such file or directory ({string})")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", help='file or directory to analyse', type=input_path)
    parser.add_argument("-j", "--json", action="store_true", help='saves the result of the analysis in a JSON file in the same directory of the file(s)')
    parser.add_argument("-q", "--quiet", action="store_true", help='doesn\'t show the results on the STDOUT')

    args = parser.parse_args()
    args.input = os.path.abspath(args.input)
    files = []
    if(os.path.isfile(args.input)):
        files.append(args.input)
    else:  
        for root, _, dir_files in os.walk(args.input):
            if "." not in root and "sources" not in root:
                for file in dir_files:
                    if ".json" not in file:
                        files.append(join(root,file))
    res = {}
    for file in files:
        print(file)
        try:
            python_exe_unpack.__handle(file) 
        except Exception as e:
            res[file] = {
                "error" : str(e)
            }
            continue

        source_dir= join(os.path.dirname(file),"sources",os.path.basename(file))
        py_files = [join(source_dir, f) for f in listdir(source_dir) if (isfile(join(source_dir, f)) and '.py' in f)]
        py_script = ""
        for py_file in py_files:
            with open(py_file) as input_file:
                py_script += input_file.read()
                input_file.close()

        module = ast.parse(py_script)
        py_extr = PYExtr()
        py_extr.visit(module)
        res[file] = {
            "strings" : py_extr.strings,
            "functions" : py_extr.functions,
            "imports" : py_extr.imports,
        }
    
    json_obj =json.dumps(res, indent = 4, ensure_ascii=False)
    
    if not args.quiet:
        
        print(json_obj)

    
    if args.json:

        output_file_name = ""

        if len(files)>1:
            output_file_name = join(args.input, "0000_analisys.json")
        else:
            output_file_name = args.input + "_an.json"    

        with open(output_file_name, "wb+") as output_file:
                output_file.write(json_obj.encode())
                output_file.close()
        print(f"JSON file created: {output_file_name}")