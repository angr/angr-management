#!/usr/bin/env python3

import os

# for finding various libs
import angrmanagement
import capstone
import pyvex
import angr
import cle

def make_command():
	"""
	Create the pyinstaller command.
	"""

	# any dynamically-loaded modules have to be explicitly added
	included_data = [
		( os.path.join(os.path.dirname(angrmanagement.__file__), "resources"), "angrmanagement/resources" ),
		( os.path.join(os.path.dirname(cle.__file__), "backends/pe/relocation"), "cle/backends/pe/relocation" ),
		( os.path.join(os.path.dirname(cle.__file__), "backends/elf/relocation"), "cle/backends/elf/relocation" ),
		( os.path.join(os.path.dirname(angr.__file__), "analyses/identifier/functions"), "angr/analyses/identifier/functions" ),
		( os.path.join(os.path.dirname(angr.__file__), "procedures"), "angr/procedures" ),
	]

	# dynamically-loaded DLLs have to be explicitly added. We just include the entire lib dir.
	included_libs = [
		( os.path.join(os.path.dirname(pyvex.__file__), "lib"), "pyvex/lib" ),
		( capstone._path, "capstone/lib" ),
	]

	all_mappings = [ ':'.join(mapping) for mapping in (included_data + included_libs) ]

	# we add onefile to make a single-executable bundle, and include ipython because it's not autodetected for some reason
	args = [ "--onefile", "--hidden-import=ipykernel.datapub" ]
	for mapping in all_mappings:
		args.append("--add-data")
		args.append(mapping)
	args.append("start.py")

	return args

def make_bundle():
	"""
	Execute the pyinstaller command.
	"""
	common_args = make_command()

	print("")
	print("")
	print("CREATING LINUX BUNDLE")
	linux_args = [ "pyinstaller" ] + common_args
	os.system(" ".join(linux_args))

make_bundle()
