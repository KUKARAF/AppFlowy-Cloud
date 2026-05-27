#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   .tools/create_release.sh           → version from Cargo.toml + shortsha
#   .tools/create_release.sh <version> → use provided version

MODE="${1:-}"

if [[ -n "$MODE" && "$MODE" != *.* ]]; then
  # Treat as semver bump mode
  CURRENT=$(grep '^version =' Cargo.toml | tr -d '"' | tr -d ' ' | cut -d= -f2)
  MAJOR=$(echo "$CURRENT" | cut -d. -f1)
  MINOR=$(echo "$CURRENT" | cut -d. -f2)
  PATCH=$(echo "$CURRENT" | cut -d. -f3)
  case "$MODE" in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
    *) echo "Usage: $0 [major|minor|patch|<version>]" >&2; exit 1 ;;
  esac
  VERSION="${MAJOR}.${MINOR}.${PATCH}"
else
  if [[ -n "$MODE" ]]; then
    VERSION="$MODE"
  else
    CURRENT=$(grep '^version =' Cargo.toml | tr -d '"' | tr -d ' ' | cut -d= -f2)
    SHA=$(git rev-parse --short HEAD)
    VERSION="${CURRENT}-${SHA}"
  fi
fi

TAG="v${VERSION}"

echo "Triggering Docker build + push for ${TAG}"
gh workflow run build_test_docker_image.yaml \
  --field branch=main \
  --field debug_version="${VERSION}" \
  --field build_appflowy_cloud=true \
  --field build_appflowy_worker=true \
  --field archs="linux/amd64"

git tag -a "${TAG}" -m "Release ${TAG}"
git push origin "${TAG}"

echo ""
echo "  Docker tag: ${TAG}"
echo "  Images: ghcr.io/kukaraf/appflowy-cloud:${VERSION}, ghcr.io/kukaraf/appflowy-cloud:latest"
echo ""
