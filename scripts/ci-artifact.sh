#!/bin/sh
# Upload or download a Gitea Actions artifact via the v3 pipeline API (curl/python3).
# No Node marketplace actions.
set -eu

usage() {
  echo "usage: $0 upload <name> <file>" >&2
  echo "       $0 download <name> <file>" >&2
  exit 2
}

cmd="${1:-}"
name="${2:-}"
file="${3:-}"
[ -n "$cmd" ] && [ -n "$name" ] && [ -n "$file" ] || usage

token="${ACTIONS_RUNTIME_TOKEN:-${GITHUB_TOKEN:-${GITEA_TOKEN:-}}}"
run_id="${GITHUB_RUN_ID:-${GITEA_RUN_ID:-${FORGEJO_RUN_ID:-}}}"
runtime="${ACTIONS_RUNTIME_URL:-}"
if [ -z "$runtime" ]; then
  runtime="${GITHUB_SERVER_URL:-}/api/actions_pipeline/"
fi
case "$runtime" in
  */) ;;
  *) runtime="${runtime}/" ;;
esac
api="${runtime}_apis/pipelines/workflows/${run_id}/artifacts"

if [ -z "$token" ]; then
  echo "missing ACTIONS_RUNTIME_TOKEN/GITHUB_TOKEN for artifacts" >&2
  exit 1
fi
if [ -z "$run_id" ]; then
  echo "missing GITHUB_RUN_ID for artifacts" >&2
  exit 1
fi

json_str() {
  key="$1"
  data="$2"
  printf '%s' "$data" | tr -d '\n' | sed -n 's/.*"'"${key}"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

# Rebase API URLs onto ACTIONS_RUNTIME_URL's origin. Gitea often returns
# ROOT_URL hosts that job containers cannot reach.
abs_url() {
  u="$1"
  u="$(printf '%s' "$u" | sed 's#\\/#/#g')"
  origin="$(printf '%s' "$runtime" | sed -n 's#^\(https\{0,1\}://[^/]*\).*#\1#p')"
  case "$u" in
    http://*|https://*)
      path="$(printf '%s' "$u" | sed 's#https\{0,1\}://[^/]*##')"
      printf '%s%s' "$origin" "$path"
      ;;
    /*) printf '%s%s' "$origin" "$u" ;;
    *) printf '%s%s' "$runtime" "$u" ;;
  esac
}

auth_curl() {
  curl -fsSL --header "Authorization: Bearer ${token}" "$@"
}

case "$cmd" in
  upload)
    [ -f "$file" ] || { echo "missing file $file" >&2; exit 1; }
    python3 - "$api" "$name" "$file" "$token" "$runtime" <<'PY'
import base64, hashlib, json, os, sys, urllib.parse, urllib.request

api, name, path, token, runtime = sys.argv[1:6]
headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}


def resolve(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    rt = urllib.parse.urlparse(runtime if runtime.endswith("/") else runtime + "/")
    if not parsed.scheme:
        base = runtime if runtime.endswith("/") else runtime + "/"
        return urllib.parse.urljoin(base, url.lstrip("/"))
    return urllib.parse.urlunparse(
        (rt.scheme, rt.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


req = urllib.request.Request(
    api + "?api-version=6.0-preview",
    data=json.dumps({"Type": "actions_storage", "Name": name, "RetentionDays": 1}).encode(),
    headers=headers,
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    body = json.load(resp)
upload_url = resolve(body["fileContainerResourceUrl"])
sep = "&" if "?" in upload_url else "?"
item = urllib.parse.quote(name + "/" + os.path.basename(path), safe="")
put_url = upload_url + sep + "itemPath=" + item

data = open(path, "rb").read()
md5 = base64.b64encode(hashlib.md5(data).digest()).decode("ascii")
put_headers = {
    "Authorization": "Bearer " + token,
    "Content-Type": "application/octet-stream",
    "x-tfs-filelength": str(len(data)),
    "x-actions-results-md5": md5,
    "Content-Range": "bytes 0-%d/%d" % (len(data) - 1, len(data)),
}
req = urllib.request.Request(put_url, data=data, headers=put_headers, method="PUT")
with urllib.request.urlopen(req) as resp:
    resp.read()

patch = api + "?api-version=6.0-preview&artifactName=" + urllib.parse.quote(name)
req = urllib.request.Request(patch, data=b"", headers={"Authorization": "Bearer " + token}, method="PATCH")
with urllib.request.urlopen(req) as resp:
    resp.read()
print("uploaded", name, path)
PY
    ;;
  download)
    list_json="$(auth_curl "${api}?api-version=6.0-preview")"
    container="$(json_str fileContainerResourceUrl "$list_json")"
    if [ -z "$container" ]; then
      echo "artifact list missing fileContainerResourceUrl: $list_json" >&2
      exit 1
    fi
    container="$(abs_url "$container")"
    sep='?'
    case "$container" in
      *\?*) sep='&' ;;
    esac
    items_json="$(auth_curl "${container}${sep}itemPath=${name}")"
    loc="$(json_str contentLocation "$items_json")"
    if [ -z "$loc" ]; then
      echo "artifact items missing contentLocation: $items_json" >&2
      exit 1
    fi
    loc="$(abs_url "$loc")"
    mkdir -p "$(dirname "$file")"
    auth_curl -o "$file" "$loc"
    echo "downloaded $name -> $file"
    ls -l "$file"
    ;;
  *)
    usage
    ;;
esac
