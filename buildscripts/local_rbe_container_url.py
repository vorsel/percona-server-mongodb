#!/usr/bin/env python3

import os
import pathlib
import subprocess
import sys

# Pulled from bazel/utils.bzl
_DISTRO_PATTERN_MAP = {
    "Ubuntu 18*": "ubuntu18",
    "Ubuntu 20*": "ubuntu20",
    "Ubuntu 22*": "ubuntu22",
    "Pop!_OS 22*": "ubuntu22",
    "Ubuntu 24*": "ubuntu24",
    "Ubuntu 26*": "ubuntu26",
    "Amazon Linux 2": "amazon_linux_2",
    "Amazon Linux 2023": "amazon_linux_2023",
    "Debian GNU/Linux 10": "debian10",
    "Debian GNU/Linux 12": "debian12",
    "Debian GNU/Linux 13": "debian13",
    "Red Hat Enterprise Linux 8*": "rhel8",
    "Red Hat Enterprise Linux 9*": "rhel9",
    "Red Hat Enterprise Linux 10*": "rhel10",
    "Oracle Linux Server 8*": "rhel8",
    "Oracle Linux Server 9*": "rhel9",
    "Oracle Linux Server 10*": "rhel10",
    "Fedora*": "rhel10",
    "SLES 15*": "suse15",
    "SLES 16*": "suse16",
}


def get_host_distro_major_version():
    # This code in this function looks a little janky in python.
    # That's because it was pulled from starlark in bazel/utils.bzl to make sure the logic matches exactly.
    if sys.platform != "linux":
        return "UNKNOWN"

    result = subprocess.run(
        [
            "sed",
            "-n",
            '/^\\(NAME\\|VERSION_ID\\)=/{s/[^=]*=//;s/"//g;p}',
            "/etc/os-release",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(
            f"Failed to determine system distro, parsing os-release failed with the error: {result.stderr}"
        )
        return "UNKNOWN"

    distro_seq = result.stdout.splitlines()
    if len(distro_seq) != 2:
        print(f"Failed to determine system distro, parsing os-release returned: {result.stdout}")
        return "UNKNOWN"

    distro_str = "{distro_name} {distro_version}".format(
        distro_name=distro_seq[0],
        distro_version=distro_seq[1],
    )

    for distro_pattern, simplified_name in _DISTRO_PATTERN_MAP.items():
        if "*" in distro_pattern:
            prefix_suffix = distro_pattern.split("*")
            if distro_str.startswith(prefix_suffix[0]) and distro_str.endswith(prefix_suffix[1]):
                return simplified_name
        elif distro_str == distro_pattern:
            return simplified_name
    return "UNKNOWN"


def _load_containers(file_name, var_name):
    container_file_path = os.path.join(
        pathlib.Path(__file__).parent.parent.resolve(),
        "bazel",
        "platforms",
        file_name,
    )
    scope = {}
    with open(container_file_path, "r", encoding="utf-8") as f:
        code = compile(f.read(), container_file_path, "exec")
        exec(code, {}, scope)
    return scope[var_name]


def calculate_local_rbe_container_url():
    host_distro = get_host_distro_major_version()
    if host_distro == "UNKNOWN":
        print("Could not determine host distro, cannot determine local RBE container URL")
        return "UNKNOWN"
    # PSMDB images first, same order as bazel/platforms/local_config_platform.bzl,
    # so the sysroot comes from the image remote execution actually runs in
    for file_name, var_name in (
        ("psmdb_rbe_containers.bzl", "PSMDB_REMOTE_EXECUTION_CONTAINERS"),
        ("remote_execution_containers.bzl", "REMOTE_EXECUTION_CONTAINERS"),
    ):
        containers = _load_containers(file_name, var_name)
        if host_distro in containers:
            return containers[host_distro]["container-url"].replace("docker://", "")
    print(f"Host distro '{host_distro}' does not have a corresponding RBE container")
    return "UNKNOWN"
