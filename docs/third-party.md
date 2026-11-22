# Dados de terceiros embutidos

O código do CoreRouter é AGPL (`LICENSE`); as dependências Rust vêm com as próprias licenças,
listadas no `Cargo.lock` e nos pacotes. Este arquivo registra os **dados** de terceiros que vão
dentro do programa: de onde vieram, quando, com qual hash e sob quais termos.

## Lista pública MA-L (OUI) do IEEE — `crates/model/data/oui.bin`

Usada para mostrar o fabricante de um MAC (IP › ARP, `ip.arp.list` → `vendor`; G1.27d).

| Campo | Valor |
|---|---|
| Fonte | `https://standards-oui.ieee.org/oui/oui.csv` (IEEE Registration Authority, registro MA-L) |
| Página do registro | https://standards.ieee.org/products-programs/regauth/ |
| Baixado em | 2026-10-27T19:59:35Z |
| Tamanho | 3 865 347 bytes |
| SHA-256 | `e1a07d9a9b6fd85c15523074414a27e9f01ed564f6172e2b885bfe3498e25f24` |
| Atribuições | 40 410 (tabela compacta de 709 079 bytes: prefixo e nome da organização) |
| Gerado por | `cargo xtask oui <oui.csv> --date 2026-10-27` |

**Termos.** O site do IEEE não publica termos de uso específicos da listagem (só o aviso geral
"© Copyright 2026 IEEE – All rights reserved." no rodapé das páginas). O arquivo de copyright do
pacote Debian `ieee-data`, que redistribui a mesma listagem
([cópia](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-43/Whats-New/licenses/ieee-data.txt)),
registra para os arquivos `oui.*`: "Copyright: 2014, IEEE", "License: other" / "Public Domain", e
a declaração atribuída ao IEEE: "IEEE does not assert any copyright in the OUI Public Listing or
attempt to restrict distribution of the listing in any way." Com base nessa declaração, o
usuário decidiu embutir a tabela (2026-10-27). Só entram o prefixo e o nome da organização; o
endereço postal da listagem não é guardado.

**Atualização.** O roteador pode baixar a listagem atual direto do IEEE
(`ip.arp.vendors.update`, botão "Update vendors" em IP › ARP › Settings); a tabela baixada vale
mais que a embutida e fica em `<config-dir>/oui.bin`. Para renovar a embutida: baixe o `oui.csv`,
rode `cargo xtask oui`, atualize esta tabela (data, tamanho, SHA-256, atribuições).
