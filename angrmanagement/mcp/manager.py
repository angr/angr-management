"""Lifecycle management for the in-process MCP server of angr management."""

from __future__ import annotations

import importlib.util
import logging
import secrets
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

_l = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8642
DEFAULT_PATH = "/mcp"


def is_mcp_available() -> bool:
    """Check if the optional dependencies for running the MCP server are installed."""
    return importlib.util.find_spec("fastmcp") is not None and importlib.util.find_spec("uvicorn") is not None


class MCPServerManager:
    """
    Runs the angr-management MCP server on a daemon thread using uvicorn, bound to localhost.

    The server exposes tools that operate on the live workspace instance, plus the standalone
    angr MCP server mounted under the "angr_" prefix.
    """

    def __init__(
        self,
        workspace: Workspace,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        path: str = DEFAULT_PATH,
        auth_token: str | None = None,
    ) -> None:
        self.workspace = workspace
        self.host = host
        self.port = port
        self.path = path
        self.auth_token = auth_token
        self._server = None  # uvicorn.Server
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}{self.path}"

    @staticmethod
    def generate_auth_token() -> str:
        return secrets.token_urlsafe(32)

    def start(self, startup_timeout: float = 10.0) -> None:
        """
        Start the MCP server and block until it is accepting connections.

        :raises RuntimeError: If the server is already running or fails to start (e.g., the port
                              is already in use).
        """
        if self.running:
            raise RuntimeError("The MCP server is already running")

        import uvicorn  # pylint:disable=import-outside-toplevel

        from .server import create_server  # pylint:disable=import-outside-toplevel

        mcp = create_server(self.workspace)
        app = mcp.http_app(path=self.path)
        if self.auth_token:
            app = _BearerTokenMiddleware(app, self.auth_token)

        config = uvicorn.Config(app, host=self.host, port=self.port, log_level="warning", lifespan="on")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, name="angr-mcp-server", daemon=True)
        self._thread.start()

        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if not self._thread.is_alive():
                self._server = None
                self._thread = None
                raise RuntimeError(
                    f"The MCP server failed to start on {self.host}:{self.port}. "
                    "The port may already be in use; you can change it in Preferences."
                )
            if self._server.started:
                _l.info("MCP server listening at %s", self.url)
                return
            time.sleep(0.05)

        self.stop()
        raise RuntimeError(f"The MCP server did not start within {startup_timeout} seconds")

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the MCP server and wait for its thread to exit."""
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                _l.warning("The MCP server thread did not exit within %s seconds", timeout)
        self._server = None
        self._thread = None


class _BearerTokenMiddleware:
    """ASGI middleware that rejects HTTP requests lacking the expected bearer token."""

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode("latin-1")
            expected = f"Bearer {self.token}"
            if not secrets.compare_digest(auth, expected):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send({"type": "http.response.body", "body": b'{"error": "unauthorized"}'})
                return
        await self.app(scope, receive, send)
