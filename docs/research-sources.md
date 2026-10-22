# Fontes de pesquisa (onde procurar antes de implementar)

Atalho: `scripts/research.sh "termo"` imprime todos os links de busca abaixo já montados para o
termo (`--open` abre os principais no navegador). Veja "Pesquisa antes de implementar" em
`AGENTS.md`. Links conferidos em 2026-10-22 (HTTP 200, salvo onde indicado).

## 1. MikroTik RouterOS v7 (sempre primeiro)

| O quê | Onde |
|---|---|
| Documentação oficial (índice do RouterOS) | https://help.mikrotik.com/docs/spaces/ROS/pages/328059/RouterOS |
| Busca na documentação | `https://help.mikrotik.com/docs/dosearchsite.action?queryString=<termo>&where=ROS` |
| Changelog das versões (o que mudou na 7.x) | https://mikrotik.com/download/changelogs |
| Fórum (casos reais, bugs, pedidos) | `https://forum.mikrotik.com/search?q=<termo>` |

## 2. Outros roteadores e projetos (ideias)

| Projeto | Busca / documentação |
|---|---|
| VyOS | `https://docs.vyos.io/en/latest/search.html?q=<termo>` |
| Juniper Junos | `https://www.juniper.net/documentation/search/?q=<termo>` |
| Nokia SR Linux | https://documentation.nokia.com/srlinux/ · https://learn.srlinux.dev/ |
| OPNsense | `https://docs.opnsense.org/search.html?q=<termo>` |
| pfSense (Netgate) | `https://docs.netgate.com/pfsense/en/latest/search.html?q=<termo>` |
| OpenWrt | `https://openwrt.org/start?do=search&q=<termo>` |
| FRRouting | `https://docs.frrouting.org/en/latest/search.html?q=<termo>` |
| Cisco (bloqueia acesso automatizado; abra no navegador ou use a busca por site) | `https://html.duckduckgo.com/html/?q=site:cisco.com+<termo>` |
| Arista EOS (idem) | `https://html.duckduckgo.com/html/?q=site:arista.com+<termo>` |

## 3. Padrões e plataforma

| O quê | Onde |
|---|---|
| RFCs (IETF Datatracker) | `https://datatracker.ietf.org/doc/search?name=<termo>&rfcs=on` |
| RFCs (RFC Editor) | `https://www.rfc-editor.org/search/rfc_search_detail.php?title=<termo>` |
| Kernel Linux: redes | https://docs.kernel.org/networking/index.html |
| Manuais (`ip`, `ethtool`, `nft`…) | `https://man7.org/linux/man-pages/man8/<comando>.8.html` |
| nftables | https://wiki.nftables.org/wiki-nftables/index.php/Main_Page |

## 4. Bibliotecas Rust

| O quê | Onde |
|---|---|
| Busca de crates (API JSON; a página do crates.io exige JavaScript) | `https://crates.io/api/v1/crates?q=<termo>&per_page=10` |
| Busca de crates legível | `https://lib.rs/search?q=<termo>` |
| Documentação de crates | `https://docs.rs/releases/search?query=<termo>` |

## Dicas

- Busque o **nome do menu do RouterOS** (`ip dhcp-client`, `interface ethernet monitor`,
  `ip firewall filter`), não a descrição.
- No changelog do MikroTik, procure o termo nas versões 7.x recentes: mostra o que mudou e os
  bugs corrigidos (casos de borda que vale testar).
- Use as fontes para entender comportamento e nomes; não copie texto (o projeto é AGPL).
