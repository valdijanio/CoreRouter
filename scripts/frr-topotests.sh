#!/usr/bin/env bash
# FRR's own topotests (tests/topotests) on an FRR build, in the lab VM: the
# check of an FRR fix before it goes upstream (docs/upstream.md). The
# topotests need root (namespaces, veths), so they run in the VM.
#
#   scripts/frr-topotests.sh --host --tests <FRR tree> [--build <label>=<install root>]... <test>...
#
# <install root> is a "make install DESTDIR=<root>" of FRR configured with the
# standard paths (--prefix=/usr --sysconfdir=/etc --localstatedir=/var
# --sbindir=/usr/lib/frr); each --build runs the tests once (e.g.
# base=/srv/build/x/out-base/root fix=/srv/build/x/out-fix/root). <test> is a
# directory or file under tests/topotests (ospf_topo1, ospf_p2mp/test_x.py).
#
# The VM has FRR from its .deb, which other labs use (vtysh): it is never
# touched. Each build runs in a private mount namespace where its
# /usr/lib/frr, /usr/bin/vtysh, /usr/share/yang and a dynamic linker cache
# with its libraries are bind-mounted over the system's. pytest and the
# Python modules the topotests import go to a venv in /srv/frr-tt/venv.
set -uo pipefail

usage() {
	echo "usage: $0 --host --tests <FRR tree> --build <label>=<install root>... <test>..." >&2
	exit 2
}

[ $# -ge 1 ] || usage
mode=$1
shift
case $mode in
--host)
	tree="" builds=() tests=()
	while [ $# -gt 0 ]; do
		case $1 in
		--tests) tree=$(realpath "$2"); shift 2 ;;
		--build) builds+=("$2"); shift 2 ;;
		*) tests+=("$1"); shift ;;
		esac
	done
	[ -d "$tree/tests/topotests/lib" ] && [ ${#builds[@]} -gt 0 ] && [ ${#tests[@]} -gt 0 ] || usage
	cargo xtask vm-lab ssh 'sudo rm -rf /srv/frr-tt/run && sudo mkdir -p /srv/frr-tt/run' || exit 1
	tar c -C "$tree/tests" --exclude='*.pyc' --exclude=__pycache__ topotests |
		cargo xtask vm-lab ssh 'sudo tar x -C /srv/frr-tt/run' || exit 1
	labels=()
	for b in "${builds[@]}"; do
		label=${b%%=*} root=$(realpath "${b#*=}")
		case $label in '' | *[!a-zA-Z0-9_-]*) echo "--build: label $label" >&2; exit 2 ;; esac
		[ -x "$root/usr/lib/frr/ospfd" ] || { echo "$root: no usr/lib/frr/ospfd" >&2; exit 2; }
		tar c -C "$root" usr |
			cargo xtask vm-lab ssh "sudo mkdir -p /srv/frr-tt/run/$label && sudo tar x -C /srv/frr-tt/run/$label" || exit 1
		labels+=("$label")
	done
	exec cargo xtask vm-lab run -- bash scripts/frr-topotests.sh --vm "${labels[*]}" "${tests[@]}"
	;;
--vm) ;;
*) usage ;;
esac

[ $# -ge 2 ] || usage
labels=$1
shift
R=/srv/frr-tt/run
export DEBIAN_FRONTEND=noninteractive
# The environment check of the topotests wants gdb (for --gdb) and every daemon
# in /usr/lib/frr: build FRR with all of them (only --disable-protobuf).
command -v gdb >/dev/null && python3 -c 'import venv' 2>/dev/null ||
	apt-get -qq install -y gdb python3-venv python3-pip >/dev/null 2>&1
if [ ! -x /srv/frr-tt/venv/bin/pytest ]; then
	python3 -m venv /srv/frr-tt/venv &&
		/srv/frr-tt/venv/bin/pip -q install 'pytest>=8.3.2' 'pytest-asyncio>=0.24.0' \
			'pytest-xdist>=3.6.1' 'scapy>=2.4.5' pyyaml xmltodict ||
		{ echo "pip install failed"; exit 1; }
fi
getent passwd frr >/dev/null || { echo "no frr user (the .deb makes it)"; exit 1; }

failed=0
for label in $labels; do
	root=$R/$label
	# The build's libraries first, then the system's.
	{ echo "$root/usr/lib"; cat /etc/ld.so.conf.d/*.conf 2>/dev/null; } >"$R/ld-$label.conf"
	ldconfig -C "$R/ld-$label.cache" -f "$R/ld-$label.conf" 2>/dev/null
	echo "== $label: $("$root/usr/lib/frr/ospfd" --version 2>/dev/null | head -n 1)"
	out=$(unshare -m --propagation private -- bash -c "
		mount --bind '$R/ld-$label.cache' /etc/ld.so.cache &&
		mount --bind '$root/usr/lib/frr' /usr/lib/frr &&
		mount --bind '$root/usr/bin/vtysh' /usr/bin/vtysh &&
		mkdir -p /usr/share/yang && mount --bind '$root/usr/share/yang' /usr/share/yang &&
		/usr/lib/frr/ospfd --version | head -n 1 &&
		cd '$R/topotests' &&
		/srv/frr-tt/venv/bin/python -m pytest -q -p no:cacheprovider $* 2>&1" 2>&1)
	echo "$out" | grep -E "passed|failed|error|^FAILED|^ERROR|ospfd version" | tail -n 30
	echo "$out" >"$R/pytest-$label.log"
	echo "$out" | grep -qE "[0-9]+ (failed|error)" && failed=1
done
echo "logs: $R/pytest-<label>.log in the VM"
exit $failed
