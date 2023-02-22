"""
Running E2E Tests with infra based on Pulumi
"""

import shutil

from invoke import task
from invoke.exceptions import Exit

from .flavor import AgentFlavor
from .modules import DEFAULT_MODULES
from .test import test_flavor

@task(iterable=['tags', 'targets'])
def run(ctx, profile="", tags=[], targets=[], verbose=True, cache=False):
    """
    Run e2e tests
    """
    if shutil.which("pulumi") is None:
        raise Exit("pulumi CLI not found, Pulumi needs to be installed on the system (not handled by invoke at the moment)", 1)

    e2e_module = DEFAULT_MODULES["test/new-e2e"]
    e2e_module.condition = lambda: True
    if targets:
        e2e_module.targets = targets

    cmd = 'gotestsum --format pkgname --packages="{packages}" -- {verbose} -mod={go_mod} -vet=off -timeout {timeout} -tags {go_build_tags} {nocache}'
    args = {
        "go_mod": "mod",
        "timeout": "2h",
        "verbose": '-v' if verbose else '',
        "nocache": '-count=1' if not cache else ''
    }

    test_flavor(ctx, flavor=AgentFlavor.base, build_tags=tags, modules=[e2e_module], args=args, cmd=cmd, env=None, junit_tar="", save_result_json="", test_profiler=None)
