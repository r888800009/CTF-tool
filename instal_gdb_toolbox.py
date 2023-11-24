#!/usr/bin/env python3
import sys
import os

TOOLBOX_PATH = "~/gdb_toolbox"
TOOLBOX_PATH = os.path.expanduser(TOOLBOX_PATH)

def install_gdb_one_gadget():
    os.system(f"git clone https://github.com/0n3t04ll/OneGadgetTest.git {TOOLBOX_PATH}/OneGadgetTest")
    os.system(f"echo 'source {TOOLBOX_PATH}/OneGadgetTest/ogt.py' >> ~/.gdbinit")

def install_r809_gdb_toolbox():
    os.system(f"git clone https://github.com/r888800009/gdb_toolbox.git {TOOLBOX_PATH}/r809_gdb_toolbox")
    os.system(f"echo 'source {TOOLBOX_PATH}/r809_gdb_toolbox/fmtstr_offset.py' >> ~/.gdbinit")

def check_dependencies():
    # check apogiatzis/gdb-peda-pwndbg-gef is installed
    # we check if the gdbinit file exists and contains the following line:
    check_signature = {
        "define init-peda": False,
        "define init-pwndbg": False,
        "define init-gef": False,
    }

    check_signature = {}

    gdbinit_path = os.path.expanduser("~/.gdbinit")
    if not os.path.isfile(gdbinit_path):
        print("gdbinit file not found")
        sys.exit(1)
    
    with open(gdbinit_path, "r") as gdbinit_file:
        gdbinit_content = gdbinit_file.readlines()
        for line in gdbinit_content:
            for key in check_signature.keys():
                if key in line:
                    check_signature[key] = True

    # verify line
    for key, value in check_signature.items():
        if not value:
            print(f"'{key}' not found in gdbinit file")
            sys.exit(1)

def install():
    check_dependencies()
    install_r809_gdb_toolbox()
    install_gdb_one_gadget()

if __name__ == "__main__":
    install()
