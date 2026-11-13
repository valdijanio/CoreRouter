# Correções enviadas aos projetos de origem

Quando um defeito está num pacote de terceiros que a imagem embarca (FRR, wpa_supplicant/hostapd,
kernel, buildroot, crates), o `CLAUDE.md` manda corrigir onde ele está ("Código de terceiros: ler
o fonte e testar por dentro"). Isso dá duas coisas: um patch na imagem (`os/patches/<pacote>/`) e
a mesma correção enviada ao projeto de origem, para o patch da imagem poder sair um dia. Este
guia é o caminho do envio, escrito depois dos dois primeiros (FRR em 2026-10-29, hostap em
2026-11-12).

**Quem publica é o dono do projeto.** A sessão prepara tudo (patch, teste, texto e comandos) e
para. O envio sai da conta e com a assinatura dele; a sessão não entra na conta de ninguém nem
digita senha.

## 1. Antes de enviar

1. **Reproduza no código atual do projeto**, não só na versão da imagem: `master`/`main` do dia,
   num clone em `/srv/build/<projeto>`. Veja se já foi corrigido: `git log` do arquivo, as issues
   e os PRs (GitHub) ou o Patchwork (listas de e-mail).
2. **Ache o commit que trouxe o defeito** (`git log -S`, `git blame`) e leia a mensagem e o teste
   que vieram com ele. No hostap, o commit `cb5bb8168` ignorava scans abortados *de propósito*,
   com um teste que exigia isso. A primeira versão do nosso patch quebraria esse teste e seria
   recusada.
3. **Teste novo no formato do projeto**, que falha sem a correção e passa com ela. Rode os dois
   casos de verdade e anote os números.
4. **Rode os testes do próprio projeto** que tocam o mesmo código: no FRR, `tests/` e topotests;
   no hostap, o hwsim (seção 4).
5. **Compile do zero** antes de cada rodada (`make clean`) e confira que o binário é o certo. Um
   `make` incremental depois de `patch -R` guardou o binário velho, e o teste "com a correção"
   rodou sem ela.
6. **Mesma mudança na imagem**: o patch em `os/patches/<pacote>/` igual ao enviado (adaptado à
   versão da imagem), conferido no `os build` (o log mostra `Applying …`) e no teste da imagem.
7. **Guarde no repositório** o que foi enviado: `docs/<projeto>-upstream/`, com os patches e o
   texto (`docs/frr-upstream/`, `docs/wpa_supplicant-upstream/`).
8. **Confira o commit antes de enviar**: nada de arquivo `.orig`/`.rej` (o `patch` os deixa), o
   autor e o `Signed-off-by` com nome real e e-mail válido (seção 2).

## 2. Assinatura (`Signed-off-by`)

FRR e hostap exigem `Signed-off-by: Nome Real <e-mail>` (DCO 1.1): é a declaração de quem envia
de que pode contribuir o código. O FRR recusou o e-mail `users.noreply.github.com` ("Can we get a
valid email in the signed off line?"); o hostap não aceita pseudônimo.

A sessão monta o commit com autor provisório e **sem** `Signed-off-by`. O dono assina com o
nome e o e-mail dele, trocando o exemplo por um endereço de verdade:

```sh
git -c user.name="Nome Real" -c user.email="nome@exemplo.org" commit --amend --no-edit --reset-author -s
git log -1 --format='%an <%ae>%n%n%b' | tail -3   # confira antes de enviar
```

O que deu errado da primeira vez: o comando foi colado com o texto de exemplo (`SEU-EMAIL`) e o
commit ficou com ele no autor e no `Signed-off-by`. O `git send-email` recusou ("unable to extract
a valid address"), e nada saiu. Rodar `-s` de novo **acrescenta** outra linha em vez de trocar:
tire a errada primeiro (`git log -1 --format=%B | grep -v '^Signed-off-by:' > msg` e
`git commit --amend -F msg`).

## 3. Por projeto

### FRR — Pull Request no GitHub

- Issue com a reprodução e PR a partir de um fork da conta do dono; texto e patches em
  `docs/frr-upstream/`.
- **Estilo:** o CI deles roda `checkpatch` e o lint; o mantenedor pede para corrigir antes de
  revisar.
- **Primeira contribuição:** o workflow do PR só roda depois que um mantenedor o aprova.
- **Depois do merge:** a correção vai para o `master` (hoje 10.9.0-dev). Para chegar a uma versão
  estável (`stable/10.7`), é preciso pedir backport a um mantenedor no PR.
- Exemplo: [FRRouting/frr#24092](https://github.com/FRRouting/frr/pull/24092), aceito em
  2026-11-11 (`docs/frr-tilfa-abort.md`).
- **Testes do FRR:** os unitários (`tests/lib`, `tests/ospfd`, `tests/zebra`) rodam sem root no
  container de build (`cd tests && python3 runtests.py …`, o que o `make check` faz; o
  `make check` sozinho só compila). Os topotests precisam de root: `scripts/frr-topotests.sh
  --host --tests <árvore do FRR> --build base=<DESTDIR> --build fix=<DESTDIR> <teste>…` os roda na
  VM do laboratório, cada build num namespace de montagem próprio, sem tocar no FRR do `.deb` da VM
  (que outros laboratórios usam). O build tem de ter os caminhos padrão (`--prefix=/usr
  --sysconfdir=/etc --localstatedir=/var --sbindir=/usr/lib/frr`).
- **Estilo antes do envio:** `perl tools/checkpatch.pl --no-tree --no-signoff <patch>`, `git
  clang-format` com o `.clang-format` do FRR (o binário 18 do PyPI, num venv em `/srv/build`) e
  `black` nos topotests.

### hostap (wpa_supplicant e hostapd) — patch por e-mail

O hostap não aceita PR no GitHub. As regras estão no arquivo `CONTRIBUTIONS` do repositório:
patch **inline** contra o `main`, de preferência com `git send-email`, para
`hostap@lists.infradead.org`. Os patches aparecem no Patchwork
(<https://patchwork.ozlabs.org/project/hostap/list/>), e a resposta do mantenedor chega por
e-mail a quem enviou.

**Uma vez por máquina:** `sudo apt install git-email` (o dono roda).

**Uma vez por conta:** inscrever-se na lista, senão cada envio espera um moderador. A inscrição
pela página da lista foi desligada ("Due to abuse, the web-based subscription has been
disabled"): mande um e-mail em **texto simples** para `hostap-join@lists.infradead.org` com só a
palavra `subscribe` no corpo e confirme a resposta que chega. A lista tem bastante tráfego; o
resumo diário se liga nas opções da inscrição.

**Senha do Gmail:** o servidor do Gmail só aceita uma **senha de app** (16 letras, sem os
espaços), criada em <https://myaccount.google.com/apppasswords>, que exige a verificação em duas
etapas ligada. A senha normal da conta dá `5.7.8 Username and Password not accepted`.

**O envio** (o dono roda, no clone com o commit assinado):

```sh
cd /srv/build/hostap
git send-email --to=hostap@lists.infradead.org \
  --smtp-server=smtp.gmail.com --smtp-server-port=587 --smtp-encryption=tls \
  --smtp-user=<e-mail do Gmail> HEAD~1
```

- Ele mostra o e-mail e pergunta "Send this email?": `y`. Depois pede a senha de app.
- `Cc:` com o próprio e-mail é normal: vem do `Signed-off-by`.
- Se o nome no `From:` do envio for diferente do autor, o `git send-email` põe uma linha `From:`
  no corpo, e é dela que o hostap tira o autor.
- `Result: 250` = o Gmail aceitou. Sem inscrição, a mensagem só aparece no arquivo da lista e no
  Patchwork depois da moderação.

**Versão 2:** se pedirem mudança, a sessão ajusta o mesmo commit (`git commit --amend`) e o
reenvio leva `--subject-prefix="PATCH v2"`, com uma nota do que mudou abaixo da linha `---`
(fica fora do commit).

## 4. Testes do hostap no laboratório (hwsim)

`scripts/hostap-hwsim.sh` roda a suíte `tests/hwsim` do hostap num clone, dentro da VM do
laboratório (o `mac80211_hwsim` precisa de root):

```sh
scripts/hostap-hwsim.sh --host /srv/build/hostap --diff <correção.diff> --repeat 5 \
  scan_aborted_on_connect_no_reselect scan_aborted_externally_on_connect
```

- Os nomes dos testes vão sem o prefixo `test_`; `'scan*'` pega todos os que começam assim. O `-l`
  do `run-tests.py` é uma lista de módulos, não a pasta de log.
- **Com `--diff`:** depois das rodadas com a correção, reverte o diff, compila de novo e roda os
  testes mais uma vez, onde o teste novo precisa falhar. No fim, o diff volta.
- **Dependências** (o script instala na VM): libnl, OpenSSL, D-Bus, pcap, curl/xml2, `binutils-dev`
  (as configurações de teste ligam `CONFIG_WPA_TRACE_BFD`), `iw` e os módulos Python que os testes
  importam (`pycryptodome`, `pyrad`, `cryptography`, `openssl`, `netifaces`, `dbus`, `gi`).
- **Política de D-Bus:** sem `dbus-wpa_supplicant.conf` em `/etc/dbus-1/system.d/`, o
  wpa_supplicant não registra o nome no barramento, e o `start.sh` falha com "Could not connect to
  /tmp/wpas-wlan0". O script instala a política.
- **No fim, `vm-lab reset`:** a suíte descarrega o `cfg80211` e deixa o domínio regulatório para
  trás. Sem o reset, o `wifi-bond-lab` seguinte viu os canais 36 e 149 como só passivos e os APs
  não subiram.
- **Teste que depende do país:** um scan de todas as faixas no hwsim levou 3,7 s numa rodada e
  mais de 9 s noutra, conforme o que o teste anterior deixou. Restrinja o teste a poucos canais
  (`scan_freq`).

## Envios

| Data | Projeto | O quê | Onde | Estado |
|---|---|---|---|---|
| 2026-10-29 | FRR | ospfd: TI-LFA não aborta sem a router-LSA (G3.4l) | [FRRouting/frr#24092](https://github.com/FRRouting/frr/pull/24092) | no `master` em 2026-11-11; fora de versão e do `stable/10.7` |
| 2026-11-12 | hostap | wpa_supplicant: scan novo depois de um abort de fora (`fix-wpa-rescan-upstream`) | lista `hostap@lists.infradead.org`; `docs/wpa_supplicant-upstream/` | enviado (`Result: 250`); esperando moderação e revisão |
| 2026-11-13 | FRR | lib/ospfd/zebra: milhares de interfaces OSPF sem crescer ao quadrado (G3.4q) | `docs/frr-upstream/ospfd-many-interfaces/` (três PRs) | preparado; a enviar pelo usuário |
