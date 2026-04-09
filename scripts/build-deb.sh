#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v dpkg-buildpackage >/dev/null 2>&1; then
  echo "dpkg-buildpackage is required (install: sudo apt install dpkg-dev debhelper dh-python pybuild-plugin-pyproject python3-hatchling)"
  exit 1
fi

chmod +x debian/rules
if [ -f debian/tests/smoke ]; then
  chmod +x debian/tests/smoke
fi

echo "Building attackcastle Debian package..."
dpkg-buildpackage -us -uc -b

echo
echo "Build complete. Artifacts should be in:"
echo "  $(cd .. && pwd)"
