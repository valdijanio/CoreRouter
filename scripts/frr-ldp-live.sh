#!/usr/bin/env bash
# G3.5: hal-frr's LDP over OSPF against a real FRR, with a ping through the
# LSP. Runs as root inside the lab VM only:
#   cargo xtask vm-lab run -- scripts/frr-ldp-live.sh
# Three LSRs in a line; R1 is the VM's FRR, driven by the test:
#   R1 (10.255.0.1, crldp-lo) —crldp-a/b 10.0.12.0/30— R2 (ns crldp2)
#      —crldp-c/d 10.0.23.0/30— R3 (ns crldp3, 10.255.0.3 on lo)
# R2 and R3 are a zebra + ospfd + ldpd of their own FRR instance (-N). From
# R1, 10.255.0.3 goes out with R2's label; R2 pops it (R3 asked for
# implicit null, RFC 3032 §2.1), so the ping crosses one label switch.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run inside the lab VM (cargo xtask vm-lab run)"; exit 1; }
modprobe mpls_router
modprobe mpls_iptunnel
sed -i "s/^ospfd=no/ospfd=yes/; s/^ldpd=no/ldpd=yes/" /etc/frr/daemons
[ -f /etc/frr/frr.conf.crorig ] || cp -p /etc/frr/frr.conf /etc/frr/frr.conf.crorig
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
cleanup() {
  pkill -f -- "-N crldp" 2>/dev/null || true
  ip netns del crldp2 2>/dev/null || true
  ip netns del crldp3 2>/dev/null || true
  ip link del crldp-a 2>/dev/null || true
  ip link del crldp-lo 2>/dev/null || true
}
cleanup
sysctl -qw net.mpls.platform_labels=1048575
ip link add crldp-lo type dummy
ip addr add 10.255.0.1/32 dev crldp-lo
ip link set crldp-lo up
ip netns add crldp2
ip netns add crldp3
ip link add crldp-a type veth peer name crldp-b netns crldp2
ip -n crldp2 link add crldp-c type veth peer name crldp-d netns crldp3
ip addr add 10.0.12.1/30 dev crldp-a
ip link set crldp-a up
sysctl -qw net.mpls.conf.crldp-a.input=1
ip -n crldp2 addr add 10.0.12.2/30 dev crldp-b
ip -n crldp2 addr add 10.0.23.1/30 dev crldp-c
ip -n crldp2 addr add 10.255.0.2/32 dev lo
ip -n crldp3 addr add 10.0.23.2/30 dev crldp-d
ip -n crldp3 addr add 10.255.0.3/32 dev lo
for ns in crldp2 crldp3; do
  ip -n $ns link set lo up
  ip netns exec $ns sysctl -qw net.mpls.platform_labels=1048575
done
ip -n crldp2 link set crldp-b up
ip -n crldp2 link set crldp-c up
ip -n crldp3 link set crldp-d up
ip netns exec crldp2 sysctl -qw net.mpls.conf.crldp-b.input=1 net.mpls.conf.crldp-c.input=1
ip netns exec crldp3 sysctl -qw net.mpls.conf.crldp-d.input=1

# lsr <ns> <id> <interfaces…>: zebra, ospfd and ldpd of instance <ns>.
lsr() {
  local ns=$1 id=$2; shift 2
  local d=/etc/frr/$ns
  install -d -o frr -g frr "$d" "/var/run/frr/$ns"
  touch "$d/zebra.conf"
  {
    for i in "$@"; do
      printf 'interface %s\n ip ospf network point-to-point\n ip ospf hello-interval 1\n' "$i"
      printf ' ip ospf dead-interval 4\n ip ospf area 0.0.0.0\nexit\n'
    done
    printf 'interface lo\n ip ospf area 0.0.0.0\n ip ospf passive\nexit\n'
    printf 'router ospf\n ospf router-id %s\nexit\n' "$id"
  } > "$d/ospfd.conf"
  {
    printf 'mpls ldp\n router-id %s\n address-family ipv4\n' "$id"
    printf '  discovery transport-address %s\n' "$id"
    for i in "$@"; do printf '  interface %s\n' "$i"; done
    printf ' exit-address-family\nexit\n'
  } > "$d/ldpd.conf"
  chown frr:frr "$d"/*.conf
  ip netns exec "$ns" /usr/lib/frr/zebra -N "$ns" -d -f "$d/zebra.conf"
  sleep 1
  ip netns exec "$ns" /usr/lib/frr/ospfd -N "$ns" -d -f "$d/ospfd.conf"
  ip netns exec "$ns" /usr/lib/frr/ldpd -N "$ns" -d -f "$d/ldpd.conf"
}
lsr crldp2 10.255.0.2 crldp-b crldp-c
lsr crldp3 10.255.0.3 crldp-d

systemctl reset-failed frr 2>/dev/null || true
systemctl restart frr
for _ in $(seq 50); do [ -S /var/run/frr/ldpd.vty ] && [ -S /var/run/frr/ospfd.vty ] && break; sleep 0.2; done
status=0
COREROUTER_FRR_LIVE=1 cargo test -p corerouter-hal-frr --test frr_ldp_live -- --nocapture || status=$?
if [ $status != 0 ]; then
  for ns in crldp2 crldp3; do
    echo "--- $ns ---"
    vtysh -N $ns -c "show mpls ldp neighbor" -c "show mpls table" -c "show ip route" 2>/dev/null || true
    ip -n $ns -f mpls route show || true
  done
  echo "--- R1 (the VM's FRR) ---"
  ip -f mpls route show || true
  vtysh -c "show ip ospf neighbor" -c "show ip ospf mpls ldp-sync" -c "show mpls ldp igp-sync" \
    -c "show mpls ldp neighbor" -c "show mpls ldp discovery" -c "show ip route" \
    -c "show running-config" || true
fi
cleanup
cp -p /etc/frr/frr.conf.crorig /etc/frr/frr.conf
systemctl restart frr || true
exit $status
