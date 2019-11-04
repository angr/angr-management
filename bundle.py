#!/usr/bin/env python3

import sys
import os

# for finding various libs
import angrmanagement
import capstone
import unicorn
import pyvex
import angr
import cle
import z3

def make_common_options():
    """
    Create the pyinstaller command.
    """

    # any dynamically-loaded modules have to be explicitly added
    included_data = [
        ( os.path.join(os.path.dirname(angrmanagement.__file__), "resources"), "angrmanagement/resources" ),
        ( os.path.join(os.path.dirname(angrmanagement.__file__), "resources/images"), "angrmanagement/resources/images" ),
        ( os.path.join(os.path.dirname(angrmanagement.__file__), "plugins"), "angrmanagement/plugins" ),
        ( os.path.join(os.path.dirname(angrmanagement.__file__), "config"), "angrmanagement/config" ),
        ( os.path.join(os.path.dirname(cle.__file__), "backends/pe/relocation"), "cle/backends/pe/relocation" ),
        ( os.path.join(os.path.dirname(cle.__file__), "backends/elf/relocation"), "cle/backends/elf/relocation" ),
        ( os.path.join(os.path.dirname(angr.__file__), "analyses/identifier/functions"), "angr/analyses/identifier/functions" ),
        ( os.path.join(os.path.dirname(angr.__file__), "procedures"), "angr/procedures" ),
    ]

    # dynamically-loaded DLLs have to be explicitly added. We just include the entire lib dir.
    included_libs = [
        ( os.path.join(os.path.dirname(pyvex.__file__), "lib"), "pyvex/lib" ),
        ( os.path.join(os.path.dirname(unicorn.__file__), "lib"), "unicorn/lib" ),
        ( capstone._path, "capstone/lib" ),
        ( os.path.join(os.path.dirname(z3.__file__), "lib"), "z3/lib" ),
    ]

    all_mappings = [ (';' if sys.platform.startswith('win') else ':').join(mapping) for mapping in (included_data + included_libs) ]

    # we add onefile to make a single-executable bundle, and include ipython because it's not autodetected for some reason
    args = [ "--name=angr-management", "--onefile", "--hidden-import=ipykernel.datapub" ]
    for mapping in all_mappings:
        args.append("--add-data")
        args.append(mapping)
    args.append("start.py")

    return args

def make_bundle():
    """
    Execute the pyinstaller command.
    """
    common_args = make_common_options()

    print("")
    print("")
    if sys.platform.startswith('linux'):
        print("CREATING LINUX BUNDLE")
        linux_args = [ "pyinstaller" ] + common_args
        os.system(" ".join(linux_args))
    elif sys.platform.startswith('win') or sys.platform.startswith('darwin'):
        print("CREATING %s BUNDLE" % sys.platform)
        windows_args = [ "pyinstaller", "-w",
                         "-i", os.path.join(os.path.dirname(angrmanagement.__file__), "resources", "images", "angr.ico")
                         ] + common_args
        os.system(" ".join(windows_args))
    else:
        print("UNSUPPORTED PLATFORM")


make_bundle()
