import logging

try:
    # we need to import the plugin to register it
    from binsync.decompilers.angr.plugin import BinSyncPlugin  # noqa: F401
except ImportError:
    logging.getLogger(__name__).error(
        "[!] BinSync is not installed, please `pip install binsync` for THIS python interpreter"
    )
