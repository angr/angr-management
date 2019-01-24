#!/usr/bin/env python3

from angrmanagement.__main__ import main

if __name__ == '__main__':
    import argparse
    import runpy

    parser = argparse.ArgumentParser(description="angr management")
    parser.add_argument("-s", "--script", type=str, help="run a python script in the (commandline) angr environment")
    parser.add_argument("-i", "--interactive", action='store_true', help="interactive (ipython) mode")
    parser.add_argument("-n", "--no-gui", action='store_true', help="run in headless mode")
    parser.add_argument("binary", nargs="?", help="the binary to open (for the GUI)")

    args = parser.parse_args()

    if args.script:
        script_globals = runpy.run_path(args.script)
    if args.interactive:
        if args.script:
            print("Your script's globals() dict is available in the `script_globals` variable.")
        import IPython
        IPython.embed(banner1="")
    if not args.no_gui:
        main(args.binary)
