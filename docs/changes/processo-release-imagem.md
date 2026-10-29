id: processo
history: G1.6s criado (opção B da release da imagem: CI compila sem assinar, o dono confere a reprodutibilidade e assina)

Release da imagem do roteador com chave própria, fora do CI. `cargo xtask os release-key init`
gera o par de **release** (Ed25519) numa pasta fora do repositório e do `/srv/build` (padrão
`~/.config/corerouter/release-key/`, 0700), com a privada cifrada por senha (Argon2id 128 MiB +
ChaCha20-Poly1305; `release-key check` confere um backup); a pública vai para
`os/keys/release/<id>.pub` por PR, e o `os check` recusa outro arquivo ali. A imagem de
desenvolvimento confia na chave de dev **e** nas de release (a VM de teste segue aceitando o
`os push`); a de release só nas de release. `cargo xtask os release --tag vX.Y.Z` confere que o
checkout é a tag (limpo, tag no `origin`, versão do workspace) e que a Release é um rascunho,
decifra a chave para o `$XDG_RUNTIME_DIR` só durante o build (apagada no fim), compila em
`<out>-release` (separado do build de dev), confere versão, commit, canal, assinatura e as
chaves confiadas do rootfs, junta os hashes ao `SHA256SUMS` do `.deb` e anexa `.crpkg`, ISO,
`.qcow2` e `.ova` ao rascunho com `gh release upload`; nunca cria tag nem publica. Passo a
passo em `docs/release.md`. Testar: `cargo test -p corerouter-image -p xtask release`; ponta a
ponta com uma chave temporária, uma tag local num clone descartável e `--dry-run`.

| G1.6s | Release da imagem, opção B: CI compila, dono assina | xtask, apps (corerouter-image), CI | O workflow de release compila a imagem da tag sem a chave de release (chave descartável) e publica os hashes de cada peça; `cargo xtask os release --verify-ci` baixa o artifact, refaz o build local, compara byte a byte (rootfs, kernel, ISO; OVA depois do G1.6l) e só então assina o manifesto e anexa ao rascunho; separar "selar" de "assinar" no `corerouter-image`; medir a reprodutibilidade entre a máquina do dono e o runner | 6 h | aberto |
