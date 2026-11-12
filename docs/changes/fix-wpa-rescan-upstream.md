id: fix-wpa-rescan-upstream

O patch do wpa_supplicant da imagem (o scan abortado que deixava a estação em SCANNING, achado no
bonding sobre Wi-Fi) passou a só pedir um scan novo quando quem abortou não foi o próprio
wpa_supplicant. A versão anterior pedia sempre e quebraria o teste `scan_aborted_on_connect_no_reselect`
do hostap, que exige o contrário depois de um `ABORT_SCAN`. Agora `wpas_abort_ongoing_scan()` marca
`scan_abort_requested`, e o scan novo, um segundo depois, sai só para um abort de fora (a interface
que desce e sobe ao entrar no bond).

A mesma mudança, contra o `main` do hostap e com o teste hwsim `scan_aborted_externally_on_connect`
(aborta o scan com `iw dev <if> scan abort` e espera a conexão), ficou pronta para a lista
`hostap@lists.infradead.org` em `docs/wpa_supplicant-upstream/`; o envio é do dono do projeto.
O defeito veio do commit `cb5bb8168` do hostap e continua no `main` (6d3d77845, 2026-11-06).

Conferido (**medido**, 2026-11-12):
- hwsim do hostap na VM do laboratório, `main` + patch: o teste novo passa 5 de 5 (conecta em 1,46 s),
  o `scan_aborted_on_connect_no_reselect` passa 5 de 5, e todos os `scan*` mais `ap_open`,
  `ap_wpa2_psk` e `sae` passam (55, 2 pulados); sem o patch o teste novo falha 2 de 2;
- imagem com o patch (aplicado ao 2.12): `cargo xtask os wifi-test` verde (179 s);
  `scripts/wifi-bond-lab.sh` verde: active-backup, balance-xor e balance-rr de pé em 7–8 s,
  20/20 pings, 1142–1673 Mbit/s, failover do active-backup com 2 de 150 pings perdidos.

O PR do FRR (G3.4l, FRRouting/frr#24092) entrou no `master` do FRR em 2026-11-11; o
`docs/frr-tilfa-abort.md` registra isso. O patch da imagem continua até uma versão do FRR que o traga.
