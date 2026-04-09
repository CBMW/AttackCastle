#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/build-apt-repo.sh \
#     --repo-root /var/www/html/apt \
#     --deb ../attackcastle_0.1.0-1_all.deb \
#     --dist stable \
#     --component main \
#     --arch all \
#     --gpg-key "YOUR-KEY-ID"

REPO_ROOT=""
DEB_PATH=""
DIST="stable"
COMPONENT="main"
ARCH="all"
GPG_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      REPO_ROOT="$2"
      shift 2
      ;;
    --deb)
      DEB_PATH="$2"
      shift 2
      ;;
    --dist)
      DIST="$2"
      shift 2
      ;;
    --component)
      COMPONENT="$2"
      shift 2
      ;;
    --arch)
      ARCH="$2"
      shift 2
      ;;
    --gpg-key)
      GPG_KEY="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

if [[ -z "$REPO_ROOT" || -z "$DEB_PATH" ]]; then
  echo "Missing required args. Use --repo-root and --deb."
  exit 1
fi

if ! command -v dpkg-scanpackages >/dev/null 2>&1; then
  echo "dpkg-scanpackages missing (install: sudo apt install dpkg-dev)"
  exit 1
fi
if ! command -v apt-ftparchive >/dev/null 2>&1; then
  echo "apt-ftparchive missing (install: sudo apt install apt-utils)"
  exit 1
fi

DEB_BASENAME="$(basename "$DEB_PATH")"
POOL_DIR="$REPO_ROOT/pool/$COMPONENT/a/attackcastle"
DIST_DIR="$REPO_ROOT/dists/$DIST/$COMPONENT/binary-$ARCH"

mkdir -p "$POOL_DIR" "$DIST_DIR"
cp -f "$DEB_PATH" "$POOL_DIR/$DEB_BASENAME"

pushd "$REPO_ROOT" >/dev/null
dpkg-scanpackages --arch "$ARCH" "pool/$COMPONENT" > "$DIST_DIR/Packages"
gzip -fk "$DIST_DIR/Packages"

apt-ftparchive release "dists/$DIST" > "dists/$DIST/Release"

if [[ -n "$GPG_KEY" ]]; then
  gpg --batch --yes --default-key "$GPG_KEY" --clearsign -o "dists/$DIST/InRelease" "dists/$DIST/Release"
  gpg --batch --yes --default-key "$GPG_KEY" -abs -o "dists/$DIST/Release.gpg" "dists/$DIST/Release"
else
  echo "No --gpg-key provided; repository metadata is unsigned."
fi
popd >/dev/null

echo "Repository metadata generated at: $REPO_ROOT"
echo "APT source line:"
echo "  deb [arch=$ARCH] <YOUR-REPO-URL> $DIST $COMPONENT"
