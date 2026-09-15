#!/bin/sh
# Restore the prepared CI tool tree packed by scripts/ci-pack.sh.
# Downloads the Gitea artifact unless CI_ENV_TAR already points at a tarball.
set -eu

archive="${CI_ENV_TAR:-ci-env.tar.gz}"
if [ ! -f "$archive" ]; then
  script_dir="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
  sh "${script_dir}/ci-artifact.sh" download ci-env "$archive"
fi

tar -xzf "$archive"
if [ ! -d .ci-env/debs ]; then
  echo "restored archive is missing .ci-env/debs" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
# All dependencies were packed from the prepare job's apt cache.
dpkg --force-depends --install .ci-env/debs/*.deb
if [ -d .ci-env/usr-local ]; then
  cp -a .ci-env/usr-local/. /usr/local/
fi
ldconfig || true
hash -r || true

command -v gcc >/dev/null
command -v cppcheck >/dev/null
command -v osv-scanner >/dev/null
command -v gitleaks >/dev/null
command -v clang-format >/dev/null
command -v make >/dev/null
