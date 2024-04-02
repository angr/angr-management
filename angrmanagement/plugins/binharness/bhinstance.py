from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

import paramiko
from binharness import AgentConnection, Environment, LocalEnvironment, Target
from binharness.bootstrap.ssh import bootstrap_ssh_environment_with_client

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class BhInstance:
    agent_connections: list[AgentConnection]
    environments: list[tuple[str, Environment]]
    local_environment: Environment
    targets: defaultdict[Environment, list[Target]]

    def __init__(self):
        self.agent_connections = []
        self.local_environment = LocalEnvironment()
        self.environments = [
            ("Local", self.local_environment),
        ]
        self.add_ssh_agent_connection("198.19.249.74", username="kevin")
        self.targets = defaultdict(list)
        log.debug("Binharness initialized")

    def load_project(self, project: angr.Project) -> Target:
        target = Target(
            self.local_environment,
            Path(project.loader.main_object.binary),
            None,
            None,
            None,
        )
        self.targets[self.local_environment].append(target)
        log.debug("Binharness loaded local target")
        return target

    def add_ssh_agent_connection(self, host: str, port: int = 60162, username: str = "root") -> AgentConnection:
        # Try to connect to the remote host directly. If that fails, use ssh bootstrap
        try:
            agent_connection = AgentConnection(host, port)
        except RuntimeError:  # Assume this means the connection failed
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect("127.0.0.1", 32222, username, key_filename="/Users/kevin/.orbstack/ssh/id_ed25519")
            assert client.exec_command("uname")[1].read().strip() == b"Linux"

            agent_binary = "/Users/kevin/workspace/binharness/target/aarch64-unknown-linux-musl/debug/bh_agent_server"
            agent_connection = bootstrap_ssh_environment_with_client(
                agent_binary, client, "198.19.249.74", listen_port=port, connect_port=port
            )
        self.agent_connections.append(agent_connection)
        self.environments.extend(
            [(f"SSH {i}", agent_connection.get_environment(i)) for i in agent_connection.get_environment_ids()]
        )
        return agent_connection
