"""Opt-in routing prefix for Bazel Remote Build Execution (RBE) worker routing.

This repo rule reads the ``RBE_CONTAINER_IMAGE_PREFIX`` environment variable
at WORKSPACE load time. When set to a non-empty string (e.g. a docker URL
stem), ``bazel/platforms/platform_util.bzl`` replaces the upstream SHA-pinned
``container-image`` exec property with a stable per-distro routing tag::

    docker://$PREFIX:$distro_or_os-$arch

RBE workers registered against that tag match actions regardless of SHA churn
in ``remote_execution_containers.bzl``. Cache invalidation is preserved via
the ``cache-silo-key`` exec property, which continues to carry the upstream
container URL so Bazel's action cache invalidates whenever upstream refreshes
the runner container.

Default (env unset) behavior is identical to MongoDB upstream: ``setup_platform``
emits the SHA-pinned URL as both the routing key and the cache handle. Safe
for fork users who do not run a custom RBE backend; no source edits needed.

The mechanism is backend-agnostic — any RBE implementation that speaks the
Bazel remote-execution gRPC API (BuildBarn, BuildGrid, EngFlow, custom
in-house servers, etc.) can consume the stable routing tag.

Activation: set ``RBE_CONTAINER_IMAGE_PREFIX`` via ``--repo_env`` or a shell
env var. See the ``psmdb_buildfarm`` config group in ``.bazelrc.psmdb`` for
the canonical Percona activation.
"""

def _impl(rctx):
    prefix = rctx.os.environ.get("RBE_CONTAINER_IMAGE_PREFIX", "")
    rctx.file("BUILD.bazel", "")
    rctx.file("defs.bzl", "RBE_CONTAINER_IMAGE_PREFIX = %r\n" % prefix)

rbe_container_routing = repository_rule(
    implementation = _impl,
    environ = ["RBE_CONTAINER_IMAGE_PREFIX"],
    configure = True,
)
