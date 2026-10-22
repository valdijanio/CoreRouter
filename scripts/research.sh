#!/usr/bin/env bash
# Prints ready-to-use search links for a feature (see docs/research-sources.md).
#
#   scripts/research.sh "dhcp client"          all links
#   scripts/research.sh --open "dhcp client"   also opens MikroTik + VyOS + OPNsense in the browser
set -euo pipefail

open=0
if [[ "${1:-}" == "--open" ]]; then open=1; shift; fi
term="${*:-}"
if [[ -z "$term" ]]; then
  echo "usage: scripts/research.sh [--open] \"term\"   (e.g. \"ip dhcp-client\")" >&2
  exit 2
fi

# Percent-encode the term (letters, digits and -._~ stay as they are).
enc() {
  local s="$1" out="" c i
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) out+=$(printf '%%%02X' "'$c") ;;
    esac
  done
  printf '%s' "$out"
}
q=$(enc "$term")

section() { printf '\n## %s\n' "$1"; }
link() { printf '  %-22s %s\n' "$1" "$2"; }

printf 'Pesquisa: "%s"\n' "$term"

section "MikroTik RouterOS v7 (primeiro)"
link "docs" "https://help.mikrotik.com/docs/dosearchsite.action?queryString=$q&where=ROS"
link "changelog 7.x" "https://mikrotik.com/download/changelogs"
link "forum" "https://forum.mikrotik.com/search?q=$q"

section "Outros roteadores (ideias)"
link "VyOS" "https://docs.vyos.io/en/latest/search.html?q=$q"
link "Juniper Junos" "https://www.juniper.net/documentation/search/?q=$q"
link "Nokia SR Linux" "https://learn.srlinux.dev/"
link "OPNsense" "https://docs.opnsense.org/search.html?q=$q"
link "pfSense" "https://docs.netgate.com/pfsense/en/latest/search.html?q=$q"
link "OpenWrt" "https://openwrt.org/start?do=search&q=$q"
link "FRRouting" "https://docs.frrouting.org/en/latest/search.html?q=$q"
link "Cisco" "https://html.duckduckgo.com/html/?q=site:cisco.com+$q"
link "Arista" "https://html.duckduckgo.com/html/?q=site:arista.com+$q"

section "Padrões e plataforma"
link "RFCs" "https://datatracker.ietf.org/doc/search?name=$q&rfcs=on"
link "kernel networking" "https://docs.kernel.org/networking/index.html"
link "nftables" "https://wiki.nftables.org/wiki-nftables/index.php/Main_Page"

section "Rust"
link "crates (API)" "https://crates.io/api/v1/crates?q=$q&per_page=10"
link "lib.rs" "https://lib.rs/search?q=$q"
link "docs.rs" "https://docs.rs/releases/search?query=$q"

if [[ $open -eq 1 ]]; then
  for u in \
    "https://help.mikrotik.com/docs/dosearchsite.action?queryString=$q&where=ROS" \
    "https://docs.vyos.io/en/latest/search.html?q=$q" \
    "https://docs.opnsense.org/search.html?q=$q"; do
    xdg-open "$u" >/dev/null 2>&1 || open "$u" >/dev/null 2>&1 || true
  done
fi
