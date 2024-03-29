from __future__ import annotations


class AngrManagementError(Exception):
    pass


class InvalidURLError(AngrManagementError):
    pass


class UnexpectedStatusCodeError(AngrManagementError):
    def __init__(self, status_code) -> None:
        super().__init__()
        self.status_code = status_code
