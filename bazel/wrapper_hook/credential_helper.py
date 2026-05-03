#!/usr/bin/env python3
"""
PSMDB-2034: Bazel CredentialHelper for the on-demand RBE buildfarm.

Implements the Bazel credential helper protocol (Bazel ≥6, design doc
https://github.com/bazelbuild/proposals/blob/main/designs/2022-06-07-bazel-credential-helpers.md):

  stdin  : {"uri": "https://bb-psmdb.ddns.net:8981/..."}
  stdout : {"headers": {"Authorization": ["Bearer <jwt>"]},
            "expires": "2026-05-03T18:30:00Z"}
  exit 0 : success — Bazel caches the headers until `expires`
  exit ≠0: error   — stderr is shown to the user

The `expires` field is what makes long builds work: Bazel honours it
and re-invokes us automatically when the deadline passes, giving us
mid-build token rotation without any tricks on the Bazel side.

Why a credential helper instead of `--remote_header=...`:

  --remote_header bakes a static Bearer into the Bazel argv at process
  start. There is no refresh point during the build — once the JWT's
  `exp` slips past now() the next gRPC call is rejected by Envoy with
  401. Builds longer than the Dex `idTokens` lifetime (~1 h) cannot
  be made to work that way without restarting Bazel.

  --credential_helper, in contrast, is invoked by Bazel each time a
  cached entry is about to expire. As long as the helper can mint a
  new token at that moment, the build keeps going.

Token sources, in priority order (first hit wins):

  (1) PSMDB_RBE_DEX_TOKEN
      Pre-exchanged Dex JWT. Used by simple CI jobs that mint and
      exchange the token outside the container and just inject the
      result. Helper returns it verbatim and lets Bazel cache up to
      its `exp - skew`.

  (2) PSMDB_RBE_JENKINS_TOKEN + PSMDB_RBE_OIDC_ISSUER + …
      Jenkins-issued OIDC subject token (RFC 8693 token-exchange).
      Helper exchanges it for a Dex token against
      $PSMDB_RBE_OIDC_ISSUER/token, file-caches the result under
      ~/.cache/rbe/ci_token.json, and returns it. Subsequent
      invocations within the cache window short-circuit; cache miss
      re-runs the exchange. Required so the CI build stays
      authenticated past the Dex token TTL while the Jenkins
      subject_token is still alive (Jenkins-side TTL must be set
      generously enough to cover the longest expected build).

  (3) Human flow
      Falls through to bazel.wrapper_hook.rbe_auth.get_cached_or_silent_refresh()
      which reads ~/.cache/rbe/token.json (seeded by `rbe_login.py`
      or by wrapper_hook.py during pre-flight) and refreshes via
      Dex's refresh_token grant if needed. Never opens a Device Code
      flow — this process has no TTY.

Output discipline:

  * stdout : ONE JSON object, nothing else (Bazel parses it strictly)
  * stderr : free-form. We funnel debug there only when
             PSMDB_RBE_HELPER_DEBUG=1 to keep noise out of normal
             builds.

No third-party deps; only stdlib (urllib, json, base64, ssl, socket)
plus a sibling import of bazel.wrapper_hook.rbe_auth.
"""

from __future__ import annotations

import base64
import datetime
import errno
import json
import os
import pathlib
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from bazel.wrapper_hook import rbe_auth  # noqa: E402

# CI cache lives next to the human cache so `rbe_login.py --status`
# and friends can pick it up if a developer ever runs the helper from
# a TTY for diagnostics. mode 0600 like the human one.
CI_CACHE_PATH = pathlib.Path.home() / ".cache" / "rbe" / "ci_token.json"

# Re-use the same skew constant the human path uses so a token that
# rbe_auth deems "stale enough to refresh" is also "stale enough to
# tell Bazel about". Keeps the two clocks aligned.
EXP_SKEW_SECONDS = rbe_auth.EXP_SKEW_SECONDS
HTTP_TIMEOUT_SECONDS = rbe_auth.HTTP_TIMEOUT_SECONDS

# Token-exchange grant URI per RFC 8693. Dex implements it when
# `oauth2.grantTypes` includes this value (see
# IaC/buildbarn/ondemand/compose/dex/dex.yaml).
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_EXCHANGE_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"

# Same name the human flow uses; the helper reads PSMDB_RBE_OIDC_ISSUER
# straight from the environment without reaching into rbe_auth's
# module-level state, so a Bazel server that already holds an
# imported copy of rbe_auth from a previous build is not poisoned.
OIDC_ISSUER_ENV = "PSMDB_RBE_OIDC_ISSUER"
OIDC_AUDIENCE_ENV = "PSMDB_RBE_OIDC_AUDIENCE"
DEX_TOKEN_ENV = "PSMDB_RBE_DEX_TOKEN"
JENKINS_TOKEN_ENV = "PSMDB_RBE_JENKINS_TOKEN"

# Public Dex client wired up for Jenkins token exchange — see the
# `bazel-jenkins` static client in dex.yaml.
JENKINS_CLIENT_ID = "bazel-jenkins"


def _debug(msg: str) -> None:
    if os.environ.get("PSMDB_RBE_HELPER_DEBUG") == "1":
        print(f"[rbe-helper] {msg}", file=sys.stderr)


# --------------------------------------------------------------------
# JWT helpers (no signature verification — Envoy validates server-side).
# --------------------------------------------------------------------
def _jwt_exp(jwt: str) -> int:
    """Return the `exp` claim (unix seconds) or 0 if undecodable."""
    try:
        _, payload_b64, _ = jwt.split(".")
    except ValueError:
        return 0
    pad = "=" * (-len(payload_b64) % 4)
    try:
        return int(json.loads(base64.urlsafe_b64decode(payload_b64 + pad)).get("exp", 0))
    except (ValueError, json.JSONDecodeError, TypeError):
        return 0


def _is_fresh(jwt: str) -> bool:
    return _jwt_exp(jwt) - int(time.time()) > EXP_SKEW_SECONDS


# --------------------------------------------------------------------
# CI cache I/O. Same atomic-replace pattern as rbe_auth._save_cache so
# parallel Bazel servers (e.g. test + build invocations) don't tear
# the file.
# --------------------------------------------------------------------
def _load_ci_cache() -> dict:
    try:
        with CI_CACHE_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_ci_cache(data: dict) -> None:
    CI_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CI_CACHE_PATH.with_suffix(CI_CACHE_PATH.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    os.replace(str(tmp), str(CI_CACHE_PATH))


# --------------------------------------------------------------------
# Token exchange (RFC 8693). Direct urllib so we don't pull deps into
# the helper subprocess that Bazel spawns potentially hundreds of
# times per build.
# --------------------------------------------------------------------
def _post_form(url: str, form: dict) -> dict:
    body = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise rbe_auth.RbeAuthError(f"HTTP {e.code} from {url}: {e.reason}")
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
        raise rbe_auth.RbeAuthError(f"network error talking to {url}: {e}")


def _exchange_jenkins_token(jenkins_jwt: str, issuer: str, audience: str) -> str:
    """Run RFC 8693 token-exchange against Dex, return the Dex id_token."""
    resp = _post_form(
        f"{issuer.rstrip('/')}/token",
        {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "client_id": JENKINS_CLIENT_ID,
            "subject_token": jenkins_jwt,
            "subject_token_type": TOKEN_EXCHANGE_TOKEN_TYPE,
            "audience": audience,
            "scope": "openid",
        },
    )
    err = resp.get("error")
    if err:
        raise rbe_auth.RbeAuthError(
            f"Dex token-exchange refused: {err}: {resp.get('error_description', '')}"
        )
    # Dex returns the new id_token in `access_token` for token-exchange
    # responses (per RFC 8693 §2.2.1) — `id_token` is also populated for
    # OIDC clients. Prefer access_token since RFC 8693 uses it as the
    # canonical exchanged-token field and Dex always sets it.
    new_token = resp.get("access_token") or resp.get("id_token")
    if not new_token:
        raise rbe_auth.RbeAuthError(f"Dex token-exchange missing token: {resp}")
    return new_token


# --------------------------------------------------------------------
# Token sources.
# --------------------------------------------------------------------
def _from_dex_env() -> str | None:
    tok = os.environ.get(DEX_TOKEN_ENV, "").strip()
    if not tok:
        return None
    if not _is_fresh(tok):
        # Operator gave us a stale token explicitly. Refuse rather
        # than emit a 401-bound build — better the loud failure than
        # the slow one.
        raise rbe_auth.RbeAuthError(
            f"{DEX_TOKEN_ENV} is set but already expired (exp={_jwt_exp(tok)}, "
            f"now={int(time.time())}). Re-export a fresh token."
        )
    _debug("using PSMDB_RBE_DEX_TOKEN (pre-exchanged Dex JWT)")
    return tok


def _from_jenkins_env() -> str | None:
    jenkins = os.environ.get(JENKINS_TOKEN_ENV, "").strip()
    if not jenkins:
        return None
    issuer = os.environ.get(OIDC_ISSUER_ENV, "").strip()
    audience = os.environ.get(OIDC_AUDIENCE_ENV, "").strip() or "bazel-jenkins"
    if not issuer:
        raise rbe_auth.RbeAuthError(
            f"{JENKINS_TOKEN_ENV} is set but {OIDC_ISSUER_ENV} is not. "
            "Set PSMDB_RBE_OIDC_ISSUER to the Dex issuer URL "
            "(e.g. https://bb-psmdb.ddns.net/dex)."
        )

    # CI cache hit: the previously exchanged Dex token is still fresh.
    cached = _load_ci_cache().get("id_token", "")
    if cached and _is_fresh(cached):
        _debug("CI cache hit (Dex token still fresh)")
        return cached

    _debug(f"exchanging Jenkins token at {issuer}/token (aud={audience})")
    new_token = _exchange_jenkins_token(jenkins, issuer, audience)
    _save_ci_cache({"id_token": new_token, "fetched_at": int(time.time())})
    return new_token


def _from_human_cache() -> str | None:
    """Use the same disk cache as the developer-facing rbe_login flow.

    Will silently refresh via the refresh_token grant; will NOT open a
    Device Code flow (we have no TTY here). If the cache is empty or
    refresh fails, returns None and lets the caller raise.
    """
    try:
        cache = rbe_auth.get_cached_or_silent_refresh()
    except rbe_auth.RbeAuthRequired:
        return None
    _debug("using human cache (~/.cache/rbe/token.json)")
    return cache.get("id_token", "") or None


# --------------------------------------------------------------------
# Bazel protocol.
# --------------------------------------------------------------------
def _expires_iso(jwt: str) -> str:
    """RFC 3339 timestamp `exp - skew` so Bazel re-invokes us in time."""
    exp = _jwt_exp(jwt)
    if exp <= 0:
        # Shouldn't happen — _is_fresh() already filtered this — but
        # be defensive: tell Bazel "5 min from now" so we get re-run
        # soon and can surface the real failure on the next call.
        exp = int(time.time()) + 300
    deadline = max(int(time.time()) + 1, exp - EXP_SKEW_SECONDS)
    return datetime.datetime.utcfromtimestamp(deadline).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_request() -> dict:
    """Read and parse the Bazel request from stdin.

    Tolerant of empty stdin (some Bazel builds invoke us with `-` only)
    so the helper doubles as a smoke-test target.
    """
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise rbe_auth.RbeAuthError(f"could not parse Bazel CredentialHelper request: {e}")


def _emit(token: str) -> None:
    """Write the Bazel CredentialHelper response to stdout."""
    payload = {
        "headers": {"Authorization": [f"Bearer {token}"]},
        "expires": _expires_iso(token),
    }
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()


def main() -> int:
    try:
        req = _read_request()
        _debug(f"request: {req!r}")

        token = _from_dex_env() or _from_jenkins_env() or _from_human_cache()
        if not token:
            print(
                "[rbe-helper] no usable PSMDB RBE credential.\n"
                "  Tried (in order):\n"
                f"    * env {DEX_TOKEN_ENV}   (not set or expired)\n"
                f"    * env {JENKINS_TOKEN_ENV}+{OIDC_ISSUER_ENV} (not set)\n"
                "    * ~/.cache/rbe/token.json (missing or refresh failed)\n"
                "  Fix: export PSMDB_RBE_DEX_TOKEN / PSMDB_RBE_JENKINS_TOKEN "
                "before invoking Bazel, or run "
                "`percona-packaging/scripts/rbe_login.py` interactively first.",
                file=sys.stderr,
            )
            return 1

        _emit(token)
        return 0

    except rbe_auth.RbeAuthError as e:
        print(f"[rbe-helper] auth error: {e}", file=sys.stderr)
        return 1
    except (BrokenPipeError, IOError) as e:
        # Bazel closed our stdout — nothing useful to do.
        if getattr(e, "errno", None) != errno.EPIPE:
            print(f"[rbe-helper] I/O error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
