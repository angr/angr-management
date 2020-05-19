
import base64
import binascii
import urllib.parse


class UrlActionBase:

    def __init__(self, md5, sha256):
        self.md5 = md5
        self.sha256 = sha256

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

    @staticmethod
    def str2addr(addr_str):
        if addr_str is None:
            return None
        try:
            addr = int(addr_str)
        except ValueError:
            addr = int(addr_str, 16)
        return addr


class UrlActionOpen(UrlActionBase):

    def __init__(self, bin_path, md5=None, sha256=None, headless=False):
        super().__init__(md5, sha256)
        self.bin_path = bin_path
        self.headless = headless

    def act(self, daemon_conn=None):
        daemon_conn.root.open(self.bin_path)

    @classmethod
    def _from_params(cls, params):
        return cls(
            cls._one_param(params, 'path'),
            md5=cls._one_param(params, 'md5_checksum'),
            sha256=cls._one_param(params, 'sha256_checksum'),
            headless=cls._one_param(params, 'headless'),
        )


class UrlActionJumpTo(UrlActionBase):

    def __init__(self, addr=None, symbol=None, md5=None, sha256=None):
        super().__init__(md5, sha256)
        self.addr = addr
        self.symbol = symbol

    def act(self, daemon_conn=None):
        daemon_conn.root.jumpto(self.addr, self.symbol, self.md5, self.sha256)

    @classmethod
    def _from_params(cls, params):

        addr = cls.str2addr(cls._one_param(params, 'addr'))

        return cls(
            addr=addr,
            symbol=cls._one_param(params, 'symbol'),
            md5=cls._one_param(params, 'md5'),
            sha256=cls._one_param(params, 'sha256'),
        )


class UrlActionCommentAt(UrlActionBase):

    def __init__(self, addr, comment, md5=None, sha256=None):
        super().__init__(md5, sha256)
        self.addr = addr
        self.comment = comment

    def act(self, daemon_conn=None):
        if self.addr is None or self.comment is None:
            return
        daemon_conn.root.commentat(self.addr, self.comment, self.md5, self.sha256)

    @classmethod
    def _from_params(cls, params):

        addr = cls.str2addr(cls._one_param(params, 'addr'))
        try:
            comment = base64.b64decode(cls._one_param(params, 'comment')).decode("utf-8")
        except (TypeError, binascii.Error):
            comment = None

        return cls(
            addr=addr,
            comment=comment,
            md5=cls._one_param(params, 'md5'),
            sha256=cls._one_param(params, 'sha256'),
        )


class UrlActionOpenBitmap(UrlActionBase):
    def __init__(self, bitmap_path, base=None, md5=None, sha256=None):
        super().__init__(md5, sha256)
        self.bitmap_path = bitmap_path
        self.base = base
        self.md5 = md5
        self.sha256 = sha256

    def act(self, daemon_conn=None):
        daemon_conn.root.openbitmap(
            self.bitmap_path, self.base, self.md5, self.sha256)

    @classmethod
    def _from_params(cls, params):
        url = cls._one_param(params, 'path')
        return cls(
            url,
            base=cls._one_param(params, 'base'),
            md5=cls._one_param(params, 'md5'),
            sha256=cls._one_param(params, 'sha256'),
        )


class UrlActionBinaryAware(UrlActionBase):
    """
    The base class of all binary-aware URl actions.
    """
    def __init__(self, md5=None, sha256=None, action=None, kwargs=None):
        super().__init__(md5, sha256)
        self.action = action
        self.kwargs = kwargs

        if not self.md5 and not self.sha256:
            raise TypeError("You must provide either MD5 or SHA256 of the target binary.")
        if not self.action:
            raise TypeError("You must provide action.")

    def act(self, daemon_conn=None):
        daemon_conn.root.custom_binary_aware_action(
            self.md5, self.sha256, self.action, self.kwargs
        )

    @classmethod
    def _from_params(cls, params):
        sha256 = cls._one_param(params, 'sha256')
        md5 = cls._one_param(params, 'md5')
        action = cls._one_param(params, 'action')
        kwargs = {}
        for k, v in params.items():
            if k not in {'sha256', 'md5', 'action'}:
                if isinstance(v, (list, tuple)):
                    kwargs[k] = v[0]
                else:
                    kwargs[k] = v
        return cls(md5=md5, sha256=sha256, action=action, kwargs=kwargs)


_ACT2CLS = {
    'open': UrlActionOpen,
    'jumpto': UrlActionJumpTo,
    'commentat': UrlActionCommentAt,
    'openbitmap': UrlActionOpenBitmap,
}


def handle_url(url, act=True):
    o = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(o.query)

    action = UrlActionBase.from_params(params)
    if act:
        action.act()
    return action


def register_url_action(action: str, action_handler: UrlActionBase):
    _ACT2CLS[action] = action_handler
