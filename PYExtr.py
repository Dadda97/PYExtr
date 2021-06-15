import json
import argparse
import os
from os.path import join
import python_exe_unpack
import shutil
import dis_custom


class PYExtr():

    def __init__(self):
        self.strings = dict()
        self.functions = dict()
        self.imports = []
        self.current_class = None

    def extract_features(self, code_obj):
        self.analyse_function(code_obj)

    def analyse_function(self, code_obj):
        parent_class = self.current_class
        if self.current_class:
            self.current_class = ".".join(
                [self.current_class, code_obj.co_name])
        else:
            self.current_class = "-GLOBAL-"

        ins_list = list(dis_custom.get_instructions(code_obj))
        opnames = []

        for i in range(len(ins_list)):
            ins = ins_list[i]
            if ins.opname == "LOAD_CONST":
                if type(ins.argval) is str:
                    if ins.argval in self.strings:
                        self.strings[ins.argval] += 1
                    else:
                        self.strings[ins.argval] = 1

            elif ins.opname == "IMPORT_NAME":
                add = ""
                if ins_list[i+1].opname == "IMPORT_FROM":
                    add = "." + ins_list[i+1].argval
                if ins_list[i+1].opname == "IMPORT_STAR":
                    add = ".*"
                self.imports.append(ins.argval+add)
            opnames.append(ins.opname)

        for const in code_obj.co_consts:
            if "code" in str(type(const)):
                self.analyse_function(const)

        self.functions[self.current_class] = "-".join(opnames)
        self.current_class = parent_class

        i += 1


def input_path(string):
    if os.path.isdir(string) or os.path.isfile(string):
        return string
    else:
        raise NameError(
            f"Cannot open input file: No such file or directory ({string})")


def analyze_file(file):
    res = dict()

    code_obj = python_exe_unpack.__handle(file)

    py_extr = PYExtr()
    try:
        py_extr.extract_features(code_obj)
        res[file] = {
            "strings": py_extr.strings,
            "functions": py_extr.functions,
            "imports": py_extr.imports,
        }
    except Exception as e:
        res[file] = {
            "error": str(e)
        }
    finally:
        file_extr_dir = os.path.join(
            os.getcwd(), "unpacked", os.path.basename(file))
        shutil.rmtree(file_extr_dir)
        return res


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?",
                        help='file or directory to analyse', type=input_path)
    parser.add_argument("-j", "--json", action="store_true",
                        help='saves the result of the analysis in a JSON file in the same directory of the file(s)')
    parser.add_argument("-q", "--quiet", action="store_true",
                        help='doesn\'t show the results on the STDOUT')

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
                        files.append(join(root, file))
    res = {}
    for file in files:
        res = {**res, **(analyze_file(file))}

    json_obj = json.dumps(res, indent=4, ensure_ascii=False)

    if not args.quiet:

        print(json_obj)

    if args.json:

        output_file_name = ""

        if len(files) > 1:
            output_file_name = join(args.input, "0000_analisys.json")
        else:
            output_file_name = args.input + "_an.json"

        with open(output_file_name, "wb+") as output_file:
            output_file.write(json_obj.encode())
            output_file.close()
        print(f"JSON file created: {output_file_name}")
