#!/usr/bin/env bash
# X-6: fail if the fake test key (or anything shaped like a real key) leaks into the repo,
# a database file, or test output. Usage: scripts/secret_scan.sh [extra paths to scan...]
set -u
fake="ghp_test_""0000"          # split so this script does not match itself
hits=0
targets=(. "$@")
if grep -rIl --exclude-dir=.git --exclude-dir=.venv --exclude-dir=node_modules --exclude-dir=__pycache__ \
     --exclude-dir=.mypy_cache --exclude-dir=.ruff_cache --exclude-dir=.pytest_cache \
     -e "$fake" -e "ghp_[A-Za-z0-9]\{30,\}" "${targets[@]}"; then
  echo "secret scan: FOUND a key-like value in the files above" >&2
  hits=1
fi
# binary files too: database fixtures and test output captured by CI
if grep -rl --binary-files=text --exclude-dir=.git --exclude-dir=.venv --include='*.db' --include='*.sqlite' \
     --include='test-output.txt' -e "$fake" "${targets[@]}"; then
  echo "secret scan: FOUND the fake key in a database or test output" >&2
  hits=1
fi
[ "$hits" -eq 0 ] && echo "secret scan: clean"
exit "$hits"
