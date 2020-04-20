
class AngrManagementError(Exception):
    pass


class InvalidURLError(AngrManagementError):
    pass


class UnexpectedStatusCodeError(AngrManagementError):
    def __init__(self, status_code, *args):
        super().__init__(*args)
        self.status_code = status_code
