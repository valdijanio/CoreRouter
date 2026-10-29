# Publicar uma versão (processo)

Uma versão do CoreRouter no GitHub Releases tem duas partes, feitas em lugares diferentes:

| Parte | Arquivos | Onde é feita | Assinatura |
|---|---|---|---|
| Gerenciador (GUI + CLI) | `corerouter-gui_<v>_amd64.deb` | CI do GitHub (`.github/workflows/release.yml`), tag `v*` | SHA-256 no `SHA256SUMS` |
| Imagem do roteador | `corerouter-<v>.crpkg`, `-install.iso`, `.qcow2`, `.ova` | **na máquina do dono** (`cargo xtask os release`) | Ed25519 com a **chave de release**, que nunca sai da máquina |

A imagem não é feita no CI: a chave que assina os pacotes do roteador não vai para um CI
público (opção A). O CI cria a Release em **rascunho**; o comando local anexa a imagem ao
rascunho; o dono revisa e publica. Nenhum comando daqui cria tag, cria Release ou publica.

## Chaves: desenvolvimento × release

O roteador só instala um `.crpkg` assinado por uma chave cuja pública a imagem **instalada**
traz em `/etc/corerouter/image-keys/` (seção "A/B e atualização segura" de
[os-image.md](os-image.md)). Há duas chaves, de dono e cuidado diferentes:

| Chave | Privada | Pública | Quem a usa |
|---|---|---|---|
| Desenvolvimento | `<out>/keys/dev-image-key.pk8`, sem senha, gerada no primeiro `os build` | `<out>/keys/pub/` | `os build`, `os push`, testes no QEMU |
| Release | `~/.config/corerouter/release-key/release-image-key.enc`, **cifrada com senha** | `os/keys/release/<id>.pub`, no repositório | só `os release` |

E quem confia em quê:

| Imagem | Confia em | Por quê |
|---|---|---|
| De desenvolvimento (`os build`, `os push`) | dev **e** release | a VM de teste aceita os pacotes do dia a dia e também uma versão publicada |
| De release (`os release`) | **só** release | um roteador de produção não aceita nada assinado pela chave de dev, que fica sem senha numa pasta de build onde várias sessões trabalham |

Esse é o padrão de quem distribui imagem assinada (chave de build separada da de release, e a
imagem publicada só com a de release): o roteador em produção não pode depender de uma chave
que mora num disco de build.

**A VM de teste (`corerouter-teste`) não muda:** ela segue aceitando `os push`, porque a chave de
dev é a mesma e as imagens de dev continuam confiando nela. Enquanto `os/keys/release/` está
vazio, a imagem de dev sai igual à de antes (só a chave de dev); depois do PR com a chave
pública, ela passa a confiar nas duas.

**Cuidado com uma VM de teste que recebe uma release:** instalar um `.crpkg` de release troca
o sistema inteiro, inclusive as chaves confiadas. Depois disso a VM só aceita pacotes de release
e o `os push` é recusado ("signed by key …, which this image does not trust"). Para testar uma
release, use outra VM (do `.qcow2` da própria release), ou volte depois com
`system.package.downgrade` (o slot anterior, de dev, confia na dev) ou reinstalando.

## A chave de release

### Gerar (uma vez)

```sh
cargo xtask os release-key init            # em ~/.config/corerouter/release-key (0700)
cargo xtask os release-key init --dir DIR  # outra pasta
```

- Pede uma senha (mínimo 12 caracteres, duas vezes, sem eco no terminal) e grava
  `release-image-key.enc` (0600) e `<id>.pub`.
- A privada é cifrada: **Argon2id** (128 MiB, 3 passadas) deriva a chave da senha, e
  **ChaCha20-Poly1305** cifra o PKCS#8 Ed25519; o cabeçalho (parâmetros, sal, nonce) é dado
  associado, então qualquer byte trocado dá "wrong passphrase". Motivo: nesta máquina rodam
  várias sessões de agente com o mesmo usuário do sistema; sem a senha, ler o arquivo não basta
  para assinar.
- O comando **recusa** pasta dentro do repositório (um `git add` de distância de um repositório
  público) e no `/srv/build` (compartilhado por todos os builds e sessões), e recusa sobrescrever
  uma chave que já existe.
- Depois, num PR, a pública vai para o repositório: `cp ~/.config/corerouter/release-key/<id>.pub
  os/keys/release/`. Ela é pública de propósito: qualquer um confere que a imagem publicada é
  assinada pela chave do repositório. O `cargo xtask os check` (que roda no CI) recusa em
  `os/keys/release/` qualquer arquivo que não seja `<id>.pub` com o id certo, e por isso uma
  `.pk8` ou `.enc` copiada ali por engano reprova o CI.

### Backup

Sem a chave **e** a senha, nenhum roteador instalado de uma release aceita outra atualização (só
reinstalando). Logo depois de gerar:

1. copie a pasta inteira para **dois** pendrives guardados em lugares diferentes, fora da rede
   (`cp -a ~/.config/corerouter/release-key /media/<pendrive>/corerouter-release-key`);
2. guarde a senha separada dos pendrives (papel, ou o gerenciador de senhas pessoal);
3. confira cada cópia: `cargo xtask os release-key check --dir /media/<pendrive>/corerouter-release-key`
   decifra só em memória (nada é gravado), diz o id e se a pública dela está em
   `os/keys/release/`; senha errada ou arquivo estragado dão "wrong passphrase".

Não ponha a pasta em nuvem, no `/srv/build`, num repositório nem na VM.

### Trocar a chave (perda ou suspeita)

As chaves confiadas são uma pasta: cabem várias. Para trocar com os roteadores em campo:

1. gere a nova (`--dir` noutra pasta), ponha a pública dela em `os/keys/release/` **junto** da
   antiga e publique uma versão assinada pela **antiga** (`--key-dir` da antiga): os roteadores
   que a instalam passam a confiar nas duas;
2. a versão seguinte sai assinada pela nova, e só então a antiga sai de `os/keys/release/`.

Chave antiga **vazada**: os roteadores que só confiam nela aceitam pacote de quem a tem até
serem atualizados; publique a troca o quanto antes e avise no texto da Release. Chave **perdida**
(sem backup): os roteadores de release precisam ser reinstalados pelo ISO de uma versão nova.

## Publicar uma versão, passo a passo

Pré-requisitos: chave de release gerada, a `.pub` dela já na `main`, `gh auth login` feito, a
VM de teste com o pacote de dev da `main` funcionando.

1. **Versão.** Se preciso, um PR que sobe `[workspace.package] version` no `Cargo.toml` (a tag
   tem de ser essa versão, com pré-release opcional: `v0.2.0` ou `v0.2.0-rc.1`).
2. **Tag e workflow do `.deb`.**

   ```sh
   git fetch origin
   git tag -a v0.1.0 -m "CoreRouter 0.1.0" origin/main
   git push origin v0.1.0
   ```

   O workflow `release` compila o `.deb` e cria a Release **em rascunho** com o `.deb`, o
   `SHA256SUMS` e as notas ([install-gui.md](install-gui.md), "Como uma versão é publicada").
   Espere ele terminar (Actions → release).
3. **Imagem, na sua máquina.** Num checkout limpo exatamente na tag (uma worktree descartável no
   disco de builds, para não mexer no checkout principal, que a fila mantém na `main`):

   ```sh
   git worktree add /srv/build/release-src-v0.1.0 v0.1.0
   cp -a ~/code/CoreRouter/os/dl /srv/build/release-src-v0.1.0/os/   # opcional: sem baixar de novo (os hashes são conferidos)
   cd /srv/build/release-src-v0.1.0
   cargo xtask os release --tag v0.1.0 --dry-run   # tudo menos o upload; confira a lista
   cargo xtask os release --tag v0.1.0 --no-build  # o mesmo build, agora anexado ao rascunho
   ```

   (Ou direto `cargo xtask os release --tag v0.1.0`, que compila e envia.) Ele pede a senha da
   chave antes de compilar.
4. **Revisar e publicar.** Em Releases → o rascunho → Edit: confira os arquivos
   (`.deb`, `.crpkg`, `-install.iso`, `.qcow2`, `.ova`, `SHA256SUMS` com todos), as notas, e
   teste o `.qcow2` numa VM limpa se quiser. **Publish release** é só no GitHub, por você.
5. **Limpar:** `git worktree remove /srv/build/release-src-v0.1.0`. O build de release
   (`<out>-release`) pode ficar: a próxima versão sai incremental dele.

### O que o `os release` confere e faz

1. A tag tem a forma `vX.Y.Z[-pre]` e `X.Y.Z` é a versão do workspace.
2. A tag existe no checkout **e** no `origin`, e o `HEAD` é o commit dela; o checkout não tem
   nenhuma mudança nem arquivo não rastreado (`git status --porcelain` vazio).
3. A Release da tag existe e é **rascunho** (publicada: recusa; não existe: recusa, salvo
   `--dry-run`).
4. Há pelo menos uma chave em `os/keys/release/` na tag, e a privada de `--key-dir` decifra e
   é uma delas.
5. Decifra a chave para `$XDG_RUNTIME_DIR/corerouter-release-<pid>/` (tmpfs, 0700, só pelo tempo
   do build; o arquivo é sobrescrito com zeros e apagado no fim, com erro ou sem).
6. Compila a imagem inteira numa pasta **própria**, `<out>-release` (por exemplo
   `/srv/build/os-out/release-src-v0.1.0-1a2b3c4d-release`), com Buildroot, ccache e chaves
   dela: o build de dev e a chave dele não entram. Versão do manifesto = a da tag; canal
   `stable` (ou `testing` numa pré-release).
7. Confere o que saiu: versão, commit e canal do `.crpkg`; a assinatura contra
   `os/keys/release/` (um pacote assinado pela de dev reprova); e que o rootfs só confia nas
   chaves de release.
8. Copia os arquivos com o nome da versão para `<out>-release/release/<tag>/`, baixa o
   `SHA256SUMS` do rascunho (o do `.deb`) e acrescenta os da imagem.
9. `gh release upload <tag> … --clobber` (repetir substitui só os arquivos desta imagem).

`--repo OWNER/NAME` escolhe o repositório do `gh`; `--jobs`/`--top-jobs` vão para o build.

### Quem baixa

```sh
v=0.1.0
base=https://github.com/valdijanio/CoreRouter/releases/download/v$v
curl -LO "$base/corerouter-$v.crpkg" -LO "$base/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
corerouter-cli --connect tls://<roteador>:8729 --user admin run system.package.check '{"path":"…"}'
```

O roteador confere a assinatura de qualquer forma antes de gravar um byte; o `SHA256SUMS` só
pega download corrompido.

## Depois (gap G1.6s)

**Opção B:** o CI compila a imagem **sem** assinar (ou com uma chave descartável), e o dono
confere que o build dele dá os mesmos bytes (o build é reprodutível: [os-image.md](os-image.md),
"Build reprodutível") e assina localmente só o manifesto. Ganha um build de máquina limpa e
pública, que qualquer um repete, e o dono deixa de precisar de 20 min de Buildroot por versão;
falta fixar o OVA (G1.6l), medir a reprodutibilidade entre máquinas e separar "selar" de
"assinar" no `corerouter-image` (hoje o `seal` assina na hora do `post-image.sh`).

## Pesquisa

- **Assinatura de imagem com chave fora do build.** O RAUC usa um *keyring* com vários
  certificados no sistema instalado (troca de chave = os dois no keyring por uma versão); o
  ChromeOS e o Flatcar separam chave de desenvolvimento e de release, e a imagem de produção só
  confia na de release; o OpenWrt assina os índices de pacote com `usign` (Ed25519) e uma chave
  por versão; o VyOS publica a assinatura `minisign` da ISO. Adotado: Ed25519 (já era o formato
  do `.crpkg`), uma pasta de chaves confiadas (já era), e a separação dev × release com a
  imagem de release só com a de release.
- **Chave em repouso.** Arquivo cifrado com senha, como a chave secreta do `minisign`
  (scrypt + XSalsa20) e do `age`; aqui Argon2id (já no projeto para senhas, G0.3) e
  ChaCha20-Poly1305 do `ring` (já no projeto). Token de hardware (YubiKey/PKCS#11) ficou de
  fora: mais um dispositivo e mais código para uma versão por semana; a pasta cifrada mais
  backup offline cobre o risco principal (outra sessão com o mesmo usuário lendo o arquivo).
- **O que ficou de fora:** assinatura do próprio `SHA256SUMS` (o roteador já confere o
  `.crpkg`; quem instala pelo ISO confia no HTTPS do GitHub e no hash); o `disk.img` cru (609
  MiB; o ISO e o `.qcow2` cobrem instalação e VM); editar as notas da Release pelo comando
  (o dono edita na revisão).
