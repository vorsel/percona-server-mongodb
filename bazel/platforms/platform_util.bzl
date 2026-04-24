load("//bazel/platforms:remote_execution_containers.bzl", "REMOTE_EXECUTION_CONTAINERS")
load("@rbe_container_routing//:defs.bzl", "RBE_CONTAINER_IMAGE_PREFIX")

def setup_platform(arch, distro_or_os, cache_silo):
    # Upstream URL is both routing key AND cache-invalidation handle by default.
    # When a custom RBE routing prefix is opted in via RBE_CONTAINER_IMAGE_PREFIX
    # (see bazel/platforms/rbe_container_routing.bzl and .bazelrc.psmdb), we
    # swap the routing portion for a stable per-distro tag while keeping the
    # upstream URL as the cache-silo-key below so Bazel's action cache still
    # invalidates when upstream refreshes the runner container.
    upstream_url = REMOTE_EXECUTION_CONTAINERS[distro_or_os]["container-url"]
    if RBE_CONTAINER_IMAGE_PREFIX:
        container_image = "docker://%s:%s-%s" % (RBE_CONTAINER_IMAGE_PREFIX, distro_or_os, arch)
    else:
        container_image = upstream_url

    exec_properties = {
        "container-image": container_image,
        "dockerNetwork": "standard",

        # EngFlow's "default" pool is ARM64
        "Pool": "x86_64" if arch == "amd64" else "default",
    }

    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:arm64" if arch == "arm64" else "@platforms//cpu:x86_64",
        ":" + distro_or_os,
        ":use_mongo_toolchain",
    ]

    if cache_silo:
        exec_properties.update({"cache-silo-key": distro_or_os + "_" + arch})
    else:
        # remote execution platforms assume a given kernel version
        constraint_values.append(":kernel_version_4_4_or_greater")
        if RBE_CONTAINER_IMAGE_PREFIX:
            # Routing tag above stays stable across upstream SHA refreshes; drive
            # action-cache invalidation off the upstream URL so refreshed runner
            # containers still trigger proper re-execution.
            exec_properties["cache-silo-key"] = upstream_url

    native.platform(
        name = distro_or_os + "_" + arch + cache_silo,
        constraint_values = constraint_values,
        exec_properties = exec_properties,
    )
