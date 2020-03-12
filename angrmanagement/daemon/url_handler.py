
import urllib.parse


class UrlActionBase:

    def act(self, daemon_conn=None):
        raise NotImplementedError()

    @staticmethod
    def from_params(params):
        action = params.get('action', None)

        if action is None:
            raise ValueError("'action' is not specified.")
        if not isinstance(action, list):
            raise TypeError("Unexpected type of 'action'. Expecting a list.")
        if len(action) != 1:
            raise ValueError("We do not support multiple actions within the same URL.")
        action = action[0]

        if action not in _ACT2CLS:
            raise KeyError("Unsupported action %s." % action)
        return _ACT2CLS[action]._from_params(params)

    @staticmethod
    def _one_param(param, key):
        v = param.get(key, None)
        if v is None:
            return None
        return v[0]


class UrlActionOpen(UrlActionBase):

    def __init__(self, bin_path, md5_checksum=None, sha256_checksum=None, headless=False):
        self.bin_path = bin_path
        self.md5_checksum = md5_checksum
        self.sha256_checksum = sha256_checksum
        self.headless = headless

    def act(self, daemon_conn=None):
        daemon_conn.root.open(self.bin_path)

    @classmethod
    def _from_params(cls, params):
        return cls(
            cls._one_param(params, 'path'),
            md5_checksum=cls._one_param(params, 'md5_checksum'),
            sha256_checksum=cls._one_param(params, 'sha256_checksum'),
            headless=cls._one_param(params, 'headless'),
        )


class UrlActionJumpTo(UrlActionBase):

    def __init__(self, addr=None, symbol=None, md5_checksum=None, sha256_checksum=None):
        self.addr = addr
        self.symbol = symbol
        self.md5_checksum = md5_checksum
        self.sha256_checksum = sha256_checksum

    def act(self, daemon_conn=None):
        daemon_conn.root.jumpto(self.addr, self.symbol, self.md5_checksum, self.sha256_checksum)

    @classmethod
    def _from_params(cls, params):

        addr = None
        if 'addr' in params:
            addr_str = params['addr'][0]
            try:
                addr = int(addr_str)
            except ValueError:
                addr = int(addr_str, 16)

        return cls(
            addr=addr,
            symbol=cls._one_param(params, 'symbol'),
            md5_checksum=cls._one_param(params, 'md5'),
            sha256_checksum=cls._one_param(params, 'sha256'),
        )


_ACT2CLS = {
    'open': UrlActionOpen,
    'jumpto': UrlActionJumpTo,
}


def handle_url(url, act=True):
    o = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(o.query)

    action = UrlActionBase.from_params(params)
    if act:
        action.act()
    return action
