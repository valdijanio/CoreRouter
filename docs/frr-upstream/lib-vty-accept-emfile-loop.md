# lib: vty accept loops and logs without end when the daemon is out of file descriptors

Relato para o FRR (G3.4m), a publicar pelo usuário (`docs/upstream.md`). Texto em inglês, como
vai no GitHub.

---

**Title:** lib: `vtysh_accept()` busy-loops and floods the log on EMFILE

**Version:** FRR 10.7.1; the same code in master as of commit c9fe9ca040 (2026-10-29). Linux 6.18 and 7.0.

**What happens.** When a daemon has used up its `RLIMIT_NOFILE` (ospfd opens one write socket
per OSPF interface, `ospf_ifp_sock_init()` in `ospfd/ospf_network.c`, so ~1000 OSPF
interfaces are enough with the usual soft limit of 1024), every new vtysh connection makes the
daemon spin:

- `vtysh_accept()` (`lib/vty.c:2081`) re-arms the read event on the listening socket
  (`vty_event_serv(VTYSH_SERV, vtyserv)`, `lib/vty.c:2092`) *before* calling `accept()`;
- `accept()` fails with `EMFILE` (`lib/vty.c:2097-2104`), the connection stays in the
  listen backlog, so the socket is readable again at once;
- each turn logs `can't accept vty socket : Too many open files` with `flog_err()`.

The daemon then burns a CPU and writes the same line as fast as it can: in our lab ospfd wrote
**10 GB of log in a few minutes** (20 000 lines per 2 MB, all the same) and filled the disk.
`vty_accept()` (`lib/vty.c:1868`, the TCP vty) has the same pattern.

**How to reproduce.** `ulimit -n 1024`, start zebra and ospfd, configure ~1100 interfaces in
OSPF (`ip ospf area 0` on VLANs or dummies), then run `vtysh -c 'show version'` once: ospfd
starts logging in a loop.

**Expected.** On `EMFILE`/`ENFILE` the daemon should stop watching the listening socket for a
while (a timer, as libevent-style servers do: re-arm the read event after e.g. 100 ms), or at
least rate-limit the message, so a full descriptor table degrades the vty instead of turning
into a log flood that takes the disk with it.

**Possible fix (sketch).** In `vtysh_accept()` and `vty_accept()`, when `accept()` fails with
`EMFILE` or `ENFILE`, cancel the read event and schedule `vty_event_serv()` from a timer
(`event_add_timer_msec(..., 100)`), and log once per back-off with a rate-limited
`flog_err`.

**Our side (done in CoreRouter):** the image's init now raises `RLIMIT_NOFILE` to 16 384
before starting FRR (`apps/corerouter-init/src/plan.rs`, `NOFILE`), so the limit is not reached
below 8 192 OSPF interfaces; the loop itself is FRR's.
