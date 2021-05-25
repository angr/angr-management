from typing import TYPE_CHECKING

from .job import Job

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class FlirtSignatureRecognitionJob(Job):

    def __init__(self, on_finish=None):
        super().__init__(name="Applying FLIRT signatures", on_finish=on_finish)

    def run(self, inst: 'Instance'):
        inst.project.analyses.Flirt(r"libc_ubuntu_2004.sig")

    def finish(self, inst, result):
        super().finish(inst, result)

    def __repr__(self):
        return "FlirtSignatureRecognitionJob"
