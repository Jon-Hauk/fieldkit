#!/usr/bin/env bash
# Prove the container posture checks against a real daemon, reproducibly.
#
# evidence/container-posture.md records this proof as it was first done: by
# hand, on one host, with the console output pasted into the evidence file.
# That was true once. This script is the same experiment as a
# gate, so it is re-proven on every pull request instead of trusted from a
# transcript, and so anyone with a Docker socket can run it and get the same
# answer.
#
# The experiment, unchanged from the 2026-09-09 run:
#
#   1. baseline   run the kit against the daemon as found
#   2. workload   start one deliberately misconfigured container - privileged,
#                 pid=host, restart=always, the Docker socket bound in, /etc
#                 bound in read-only, UID 0, a floating :latest tag - and run
#                 the kit again
#   3. after      tear it down and run the kit a third time
#
# It passes only if the six workload checks each fire naming their specific
# condition, the WARN count rises by exactly the five checks that were INFO
# before (the users check was already WARN on the image list), and the third
# run reproduces the first to the digit. The last one is the negative control:
# a check that held stale results, or a teardown that left something behind,
# fails here.
#
# Read-only claims still hold for the kit. It is this harness, not the kit,
# that starts and removes a container - and only one it created, by name.
#
# Requires: bash, docker with a reachable rootful daemon, python3 (3.8+).
# Environment: PYTHON (interpreter, default python3), OUT (report directory,
# default a fresh mktemp -d). Exit 0 on proof, 1 on a failed assertion, 2 when
# the preconditions are not met.

set -euo pipefail

PYTHON="${PYTHON:-python3}"
OUT="${OUT:-$(mktemp -d)}"
NAME="fieldkit-badpost"

# The base image is pulled by digest so the harness does not itself commit the
# floating-tag mistake it is proving the kit detects. The alpine:3.20 manifest
# list, resolved from Docker Hub 2026-09-12. The floating reference the check
# must flag is the local re-tag below; nothing else is fetched.
BASE="alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

# Located relative to this file, so the same script runs from the monorepo
# (linux/tests/live/) and from the published repo (linux/tests/live/).
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/fieldkit-linux"

fail() { echo "::error::$*" >&2; exit 1; }

# --- preconditions --------------------------------------------------------

[ -f "$KIT" ] || { echo "::error::$KIT not found; run from a checkout" >&2; exit 2; }
command -v docker >/dev/null || { echo "::error::docker is not installed" >&2; exit 2; }
docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 \
  || { echo "::error::cannot reach the Docker daemon; this needs the docker group or root" >&2; exit 2; }
if docker container inspect "$NAME" >/dev/null 2>&1; then
  echo "::error::a container named $NAME already exists; refusing to reuse or remove something this run did not create" >&2
  exit 2
fi
if docker image inspect "$NAME:latest" >/dev/null 2>&1; then
  echo "::error::an image tagged $NAME:latest already exists; refusing to reuse it" >&2
  exit 2
fi

mkdir -p "$OUT"
echo "python: $("$PYTHON" --version 2>&1)"
echo "docker: $(docker info --format '{{.ServerVersion}}, security={{.SecurityOptions}}')"
echo "reports: $OUT"

# Tear down what this run created, and only that, however it exits.
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rmi "$NAME:latest" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- helpers ----------------------------------------------------------------

# Run the kit's container section and keep the console output. The kit exits
# 1 when any check is FAIL, which is a result, not a harness error; 2 is a
# report-export failure and anything else is a crash.
run_kit() {
  local label="$1" rc
  set +e
  "$PYTHON" -B "$KIT" --containers-only --report-path "$OUT/$label" > "$OUT/$label.txt" 2>&1
  rc=$?
  set -e
  case "$rc" in
    0|1) ;;
    *) cat "$OUT/$label.txt"; fail "$label: kit exited $rc" ;;
  esac
  if grep -Eq 'Traceback|check errored|check returned nothing' "$OUT/$label.txt"; then
    cat "$OUT/$label.txt"; fail "$label: the kit crashed or a check returned nothing"
  fi
  if [ "$(grep -Ec '^[0-9]+ PASS, [0-9]+ FAIL, [0-9]+ WARN, [0-9]+ UNKN, [0-9]+ INFO$' "$OUT/$label.txt")" != 1 ]; then
    cat "$OUT/$label.txt"; fail "$label: expected exactly one severity summary line"
  fi
}

summary() { grep -E '^[0-9]+ PASS, ' "$OUT/$1.txt"; }
count() { summary "$1" | grep -Eo "[0-9]+ $2" | cut -d' ' -f1; }

# Assert one check line carries a status and names a condition.
expect() {
  local label="$1" status="$2" check="$3" condition="$4"
  if ! grep -F "[$status] $check:" "$OUT/$label.txt" | grep -Fq "$condition"; then
    echo "--- $label ---"; cat "$OUT/$label.txt"
    fail "$label: expected [$status] $check naming '$condition'"
  fi
}

# --- 1. baseline --------------------------------------------------------------

# Pull before the baseline so the image list is identical in runs 1 and 3;
# only the re-tag and the container come and go between them.
docker pull -q "$BASE" >/dev/null
run_kit baseline
echo "baseline: $(summary baseline)"

# Every hosted runner and every unhardened host is in this state, and it is
# the finding the task brief called the one most likely to be got wrong:
# docker-group membership is root-equivalent and must be reported as such.
expect baseline WARN "Docker socket and group access" "root-equivalent"
expect baseline WARN "Daemon root and user namespaces" "Daemon=rootful"
expect baseline INFO "Container privilege and host namespaces" "No running containers"

# --- 2. workload --------------------------------------------------------------

docker tag "$BASE" "$NAME:latest"
docker run -d --name "$NAME" \
  --privileged --pid=host --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/hostetc:ro \
  --user 0:0 \
  "$NAME:latest" sleep 3600 >/dev/null
run_kit workload
echo "workload: $(summary workload)"

expect workload WARN "Container privilege and host namespaces" "privileged"
expect workload WARN "Container privilege and host namespaces" "pid=host"
expect workload WARN "Container Docker socket mounts" "socket exposure"
expect workload WARN "Container and image configured users" "container configured UID 0"
expect workload WARN "Container and image configured users" "image configured UID 0"
expect workload WARN "Sensitive host bind mounts" "sensitive bind (ro access)"
expect workload WARN "Sensitive host bind mounts" "sensitive bind (rw access)"
expect workload WARN "Container restart persistence" "restart=always"
expect workload WARN "Image reference provenance" "not pinned by sha256 digest"

# Exactly five checks move INFO -> WARN. "At least" would let a check that
# fires on nothing pass; "exactly" is the point of a negative control.
delta_warn=$(( $(count workload WARN) - $(count baseline WARN) ))
delta_info=$(( $(count baseline INFO) - $(count workload INFO) ))
[ "$delta_warn" = 5 ] || fail "expected WARN to rise by exactly 5 with the workload, rose by $delta_warn"
[ "$delta_info" = 5 ] || fail "expected INFO to fall by exactly 5 with the workload, fell by $delta_info"

# --- 3. after -------------------------------------------------------------------

docker rm -f "$NAME" >/dev/null
docker rmi "$NAME:latest" >/dev/null
run_kit after
echo "after:    $(summary after)"

[ "$(summary after)" = "$(summary baseline)" ] \
  || fail "teardown did not return the host to baseline: '$(summary baseline)' vs '$(summary after)'"
if ! diff <(grep -E '^\[' "$OUT/baseline.txt") <(grep -E '^\[' "$OUT/after.txt"); then
  fail "a check reported differently after teardown than at baseline (diff above)"
fi

echo
echo "Proven: six workload checks fired on a live daemon, +5 WARN / -5 INFO, and the host returned to baseline."
