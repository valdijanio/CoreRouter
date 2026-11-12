id: docs-upstream-envio

Novo guia `docs/upstream.md`: como preparar e enviar a correção de um pacote de terceiros ao
projeto de origem. Ele cobre:
- o que conferir antes (código atual do projeto, o commit que trouxe o defeito e o teste dele,
  teste novo que falha sem a correção, compilação do zero, o mesmo patch na imagem);
- a assinatura (`Signed-off-by` com nome real e e-mail válido);
- o caminho de cada projeto: FRR por PR no GitHub, hostap por e-mail com `git send-email`,
  inscrição na lista por `hostap-join@` e senha de app do Gmail;
- uma tabela dos envios.

Novo `scripts/hostap-hwsim.sh` (o usado no `fix-wpa-rescan-upstream`): roda a suíte hwsim do
hostap num clone, dentro da VM do laboratório. Instala as dependências e a política de D-Bus,
compila do zero e, com `--diff`, roda de novo sem a correção para ver o teste novo falhar. No fim,
faz `vm-lab reset`, porque a suíte deixa o `cfg80211` e o país para trás. O `CLAUDE.md` e o
`AGENTS.md` apontam o guia no item "Corrija onde está o defeito".
