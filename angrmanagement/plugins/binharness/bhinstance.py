from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from binharness import AgentConnection, Environment, LocalEnvironment, Target

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class BhInstance:
    """BhInstance holds the state of binharness associated with a single instance."""

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
