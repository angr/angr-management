from __future__ import annotations


class AngrManagementError(Exception):
    """Base class for all errors raised by angr management."""


class InvalidURLError(AngrManagementError):
    """InvalidURLError is raised when an invalid URL is provided."""


class UnexpectedStatusCodeError(AngrManagementError):
    """UnexpectedStatusCodeError is raised when an unexpected status code is
    received from an HTTP request.
    """

    def __init__(self, status_code) -> None:
        super().__init__()
        self.status_code = status_code


class ContainerAlreadyRegisteredError(AngrManagementError):
    """ContainerAlreadyRegisteredError is raised when a container is already
    registered in the container registry.
    """
