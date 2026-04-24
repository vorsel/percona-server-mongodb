"""Opt-in routing prefix for Bazel Remote Build Execution (RBE) worker routing.

This bzlmod module extension materializes a ``@rbe_container_routing``
repository whose ``:defs.bzl`` exposes ``RBE_CONTAINER_IMAGE_PREFIX`` — the
value of the identically-named environment variable at WORKSPACE load time.
When the variable is set to a non-empty string (e.g. a docker URL stem),
``bazel/platforms/platform_util.bzl`` and
``bazel/platforms/local_config_platform.bzl`` replace the upstream
SHA-pinned ``container-image`` exec property with a stable per-distro
routing tag::

    docker://$PREFIX:$distro_or_os-$arch

RBE workers registered against that tag match actions regardless of SHA
churn in ``remote_execution_containers.bzl``. Cache invalidation is
preserved via the ``cache-silo-key`` exec property, which continues to
carry the upstream container URL so Bazel's action cache invalidates
whenever upstream refreshes the runner container.

Default (env unset) behavior is identical to MongoDB upstream: the
SHA-pinned URL stays as both the routing key and the cache handle. Safe
for fork users who do not run a custom RBE backend; no source edits
needed.

The mechanism is backend-agnostic — any RBE implementation that speaks
the Bazel remote-execution gRPC API (BuildBarn, BuildGrid, EngFlow,
custom in-house servers, etc.) can consume the stable routing tag.

Activation: set ``RBE_CONTAINER_IMAGE_PREFIX`` via ``--repo_env`` or a
shell env var. See the ``psmdb_buildfarm`` config group in
``.bazelrc.psmdb`` for the canonical Percona activation.

Implementation note: this is a module_extension (not a use_repo_rule
target) to avoid a circular dependency with ``local_config_platform.bzl``
inside the synthetic ``_repo_rules`` extension bzlmod creates for all
``use_repo_rule`` sites. A standalone extension is evaluated before
``_repo_rules``, so ``@rbe_container_routing//:defs.bzl`` is already
materialized when other ``use_repo_rule`` files load it.
"""

def _repo_impl(rctx):
    prefix = rctx.os.environ.get("RBE_CONTAINER_IMAGE_PREFIX", "")
    rctx.file("BUILD.bazel", "")
    rctx.file("defs.bzl", "RBE_CONTAINER_IMAGE_PREFIX = %r\n" % prefix)

_rbe_container_routing_repo = repository_rule(
    implementation = _repo_impl,
    environ = ["RBE_CONTAINER_IMAGE_PREFIX"],
    configure = True,
)

def _ext_impl(_mctx):
    _rbe_container_routing_repo(name = "rbe_container_routing")

rbe_container_routing = module_extension(
    implementation = _ext_impl,
    environ = ["RBE_CONTAINER_IMAGE_PREFIX"],
)
