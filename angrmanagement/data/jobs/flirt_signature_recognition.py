from typing import TYPE_CHECKING
import logging

import angr.flirt

from .job import Job

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance

_l = logging.getLogger(name=__name__)


class FlirtSignatureRecognitionJob(Job):
    """
    Describes a job for using FLIRT signatures to recognize and match library functions embedded in a binary.
    """

    def __init__(self, on_finish=None):
        super().__init__(name="Applying FLIRT signatures", on_finish=on_finish)

    def _run(self, inst: 'Instance'):
        if inst.project.arch.name.lower() in angr.flirt.FLIRT_SIGNATURES_BY_ARCH:
            inst.project.analyses.Flirt()
        else:
            _l.warning("No FLIRT signatures exist for architecture %s.", inst.project.arch.name)

    def __repr__(self):
        return "FlirtSignatureRecognitionJob"
