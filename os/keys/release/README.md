# Chaves públicas de release da imagem

Cada `<id>.pub` aqui é a chave pública Ed25519 (64 dígitos hex) de uma chave de release, com o
nome = id (os 8 primeiros bytes do SHA-256 da chave, em hex). A privada nunca entra no
repositório: fica cifrada com senha na máquina do dono (`cargo xtask os release-key init`).

- Imagem de **release** (`cargo xtask os release`): confia só nestas chaves.
- Imagem de **desenvolvimento** (`cargo xtask os build`/`push`): confia na chave de
  desenvolvimento do build **e** nestas.

`cargo xtask os check` recusa qualquer outro arquivo aqui. Passo a passo em `docs/release.md`.
