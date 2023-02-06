import base64
import binascii
import urllib.parse
from typing import Dict, Optional, Type


class UrlActionBase:
    """
    The base class for URL actions.
    """

    def __init__(self, target_id: str = None):
        self.target_id = target_id

    def act(self, daemon_conn=None):
        raise NotImplementedError()

    @staticmethod
    def from_params(params):
        action = params.get("action", None)

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
    """
    Implements the open action.
    """

    def __init__(self, bin_path, target_id=None, headless=False):
        super().__init__(target_id=target_id)
        self.bin_path = bin_path
        self.headless = headless

    def act(self, daemon_conn=None):
        if self.bin_path is not None:
            daemon_conn.root.open(self.bin_path)
        else:
            print("Incomplete URL: expected `path` parameter")

    @classmethod
    def _from_params(cls, params):
        return cls(
            cls._one_param(params, "path"),
            target_id=cls._one_param(params, "target_id"),
            headless=cls._one_param(params, "headless"),
        )


class UrlActionJumpTo(UrlActionBase):
    """
    Implements the jump-to action.
    """

    def __init__(self, addr=None, symbol=None, target_id=None):
        super().__init__(target_id=target_id)
        self.addr = addr
        self.symbol = symbol

    def act(self, daemon_conn=None):
        daemon_conn.root.jumpto(self.addr, self.symbol, self.target_id)

    @classmethod
    def _from_params(cls, params):
        addr = cls.str2addr(cls._one_param(params, "addr"))

        return cls(
            addr=addr,
            symbol=cls._one_param(params, "symbol"),
            target_id=cls._one_param(params, "target_id"),
        )


class UrlActionCommentAt(UrlActionBase):
    """
    Implements the comment-at action.
    """

    def __init__(self, addr, comment, target_id=None):
        super().__init__(target_id)
        self.addr = addr
        self.comment = comment

    def act(self, daemon_conn=None):
        if self.addr is None or self.comment is None:
            return
        daemon_conn.root.commentat(self.addr, self.comment, self.target_id)

    @classmethod
    def _from_params(cls, params):
        addr = cls.str2addr(cls._one_param(params, "addr"))
        try:
            comment = base64.b64decode(cls._one_param(params, "comment")).decode("utf-8")
        except (TypeError, binascii.Error):
            comment = None

        return cls(
            addr=addr,
            comment=comment,
            target_id=cls._one_param(params, "target_id"),
        )


class UrlActionBinaryAware(UrlActionBase):
    """
    The base class of all binary-aware URL actions.
    """

    def __init__(self, target_id=None, action=None, kwargs=None):
        super().__init__(target_id)
        self.action = action
        self.kwargs = kwargs

        if not self.target_id:
            raise TypeError("You must provide the target ID.")
        if not self.action:
            raise TypeError("You must provide action.")

    def act(self, daemon_conn=None):
        daemon_conn.root.custom_binary_aware_action(self.target_id, self.action, self.kwargs)

    @classmethod
    def _from_params(cls, params):
        target_id: Optional[str] = cls._one_param(params, "target_id")
        action = cls._one_param(params, "action")
        kwargs = {}
        for k, v in params.items():
            if k not in {"target_id", "action"}:
                if isinstance(v, (list, tuple)):
                    kwargs[k] = v[0]
                else:
                    kwargs[k] = v
        return cls(target_id=target_id, action=action, kwargs=kwargs)


_ACT2CLS: Dict[str, Type[UrlActionBase]] = {
    "open": UrlActionOpen,
    "jumpto": UrlActionJumpTo,
    "commentat": UrlActionCommentAt,
}


def handle_url(url, act=True):
    o = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(o.query)

    action = UrlActionBase.from_params(params)
    if act:
        action.act()
    return action


def register_url_action(action: str, action_handler: Type[UrlActionBase]):
    _ACT2CLS[action] = action_handler
