#!/bin/sh
# Pack the prepared CI tool tree (apt .debs + /usr/local binaries) for later jobs.
set -eu

root="${1:-.}"
dest="${2:-ci-env.tar.gz}"

mkdir -p "${root}/.ci-env/debs" "${root}/.ci-env/usr-local"
# docker-clean normally deletes these; prepare removes that drop-in first.
if ! ls /var/cache/apt/archives/*.deb >/dev/null 2>&1; then
  echo "no .deb files in /var/cache/apt/archives; cannot pack CI env" >&2
  exit 1
fi
cp -a /var/cache/apt/archives/*.deb "${root}/.ci-env/debs/"
cp -a /usr/local/. "${root}/.ci-env/usr-local/"

tar -C "${root}" -czf "${dest}" .ci-env
echo "packed ${dest}"
ls -l "${dest}"
