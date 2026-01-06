#!/bin/sh
set -eu

repo="RealXuChe/codex"
channel="nightly"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --channel)
      shift
      channel="${1:-}"
      ;;
    *)
      echo "Usage: install-codex.sh [--channel nightly|alpha]" >&2
      exit 2
      ;;
  esac
  shift
done

case "$channel" in
  nightly|alpha) ;;
  *)
    echo "Unknown channel: $channel (expected nightly|alpha)" >&2
    exit 2
    ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64) ;;
  *)
    echo "Unsupported architecture: $arch (only x86_64 is supported in this fork's releases)" >&2
    exit 1
    ;;
esac

dest_dir="${HOME}/.local/bin"
dest="${dest_dir}/codex"

api_base="https://api.github.com/repos/${repo}"

fetch_release_json() {
  url="$1"
  curl -fsSL "$url"
}

release_json=""
if [ "$channel" = "nightly" ]; then
  release_json="$(fetch_release_json "${api_base}/releases/tags/fork-nightly")"
else
  releases_json="$(fetch_release_json "${api_base}/releases?per_page=100")"
  release_json="$(
    printf '%s' "$releases_json" | python3 - <<'PY'
import json
import re
import sys

releases = json.load(sys.stdin)
pattern = re.compile(r"^fork-v.*-alpha\.\d+(-\d+)?$")
for rel in releases:
    if rel.get("draft"):
        continue
    tag = rel.get("tag_name", "")
    if pattern.match(tag):
        sys.stdout.write(json.dumps(rel))
        break
else:
    sys.stderr.write("No alpha release found (tag_name matching fork-v*-alpha.*)\n")
    sys.exit(1)
PY
  )"
fi

asset_url="$(
  printf '%s' "$release_json" | python3 - <<'PY'
import json
import sys

release = json.load(sys.stdin)
assets = release.get("assets", [])

def find_asset(name):
    for asset in assets:
        if asset.get("name") == name:
            return asset.get("browser_download_url")
    return None

url = find_asset("codex-x86_64-unknown-linux-musl")
if url is None:
    url = find_asset("codex-x86_64-unknown-linux-gnu")
if url is None:
    names = [a.get("name") for a in assets]
    sys.stderr.write("No supported codex binary asset found in release. Assets: %r\n" % (names,))
    sys.exit(1)

sys.stdout.write(url)
PY
)"

tmp="${dest}.tmp.$$"
mkdir -p "$dest_dir"

echo "Downloading Codex (${channel}) to ${dest} ..."
curl -fL --retry 3 --retry-delay 2 -o "$tmp" "$asset_url"
chmod +x "$tmp"
mv -f "$tmp" "$dest"

echo "Installed: $dest"

case ":${PATH}:" in
  *":${HOME}/.local/bin:"*)
    ;;
  *)
    echo ""
    echo "Note: ~/.local/bin is not currently on PATH."
    echo "To make it available automatically on startup, you can run:"
    echo ""
    echo "  sh -c 'rc=\"$HOME/.profile\"; case \"$SHELL\" in */bash) rc=\"$HOME/.bashrc\" ;; */zsh) rc=\"$HOME/.zshrc\" ;; esac; printf \"\\n# Add ~/.local/bin to PATH (Codex)\\nexport PATH=\\\"$HOME/.local/bin:\\$PATH\\\"\\n\" >> \"$rc\"; echo \"Updated $rc\"'"
    echo ""
    echo "Then restart your shell (or open a new terminal)."
    ;;
esac
