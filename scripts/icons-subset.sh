#!/usr/bin/env bash
# Cuts crates/ui/assets/phosphor/Phosphor-subset.ttf from the full Phosphor
# font (regular weight), keeping only the code points crates/ui/src/icons.rs
# names (G0.23). Run it after adding an icon there, then commit both files.
#
#   scripts/icons-subset.sh /path/to/Phosphor.ttf
#
# The full font: res/Phosphor.ttf of the egui-phosphor 0.14.0 crate
# (crates.io, sha256 3f4299551488dddaa8f757727e1eb4ffdaf277ffe6e30b413403468f5ecf4634),
# Phosphor Icons, MIT. Needs fontTools' pyftsubset (pip install fonttools).
set -euo pipefail

src="${1:-}"
if [[ -z "$src" || ! -f "$src" ]]; then
  echo "usage: scripts/icons-subset.sh /path/to/Phosphor.ttf" >&2
  exit 2
fi
command -v pyftsubset >/dev/null || { echo "pyftsubset not found (pip install fonttools)" >&2; exit 1; }

root="$(cd "$(dirname "$0")/.." && pwd)"
codes="$(grep -oE '\\u\{[0-9A-Fa-f]+\}' "$root/crates/ui/src/icons.rs" | grep -oE '[0-9A-Fa-f]{4,}' | sort -u | sed 's/^/U+/' | paste -sd, -)"
[[ -n "$codes" ]] || { echo "no code points in icons.rs" >&2; exit 1; }

out="$root/crates/ui/assets/phosphor/Phosphor-subset.ttf"
mkdir -p "$(dirname "$out")"
pyftsubset "$src" --unicodes="$codes" --output-file="$out" \
  --layout-features='' --no-hinting --desubroutinize --drop-tables+=GSUB,GPOS
echo "$(wc -c <"$out") bytes, $(tr ',' '\n' <<<"$codes" | wc -l) icons -> $out"
