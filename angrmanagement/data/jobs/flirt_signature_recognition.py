from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import angr.flirt

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

_l = logging.getLogger(name=__name__)


class FlirtSignatureRecognitionJob(InstanceJob):
    """
    Describes a job for using FLIRT signatures to recognize and match library functions embedded in a binary.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("Applying FLIRT signatures", instance, on_finish=on_finish)

    def run(self, _: JobContext) -> None:
        if self.instance.project.arch.name.lower() in angr.flirt.FLIRT_SIGNATURES_BY_ARCH:
            self.instance.project.analyses.Flirt()
        else:
            _l.warning("No FLIRT signatures exist for architecture %s.", self.instance.project.arch.name)

    def __repr__(self) -> str:
        return "FlirtSignatureRecognitionJob"
