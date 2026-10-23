//! Portuguese explanations, labels and reason templates of System ›
//! Tuning (G1.26), each sorted by key.

/// Explanations by key (`tuning.<parameter>`, `tuning.<topic>`).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "tuning.kernel.panic",
        r##"## O que faz
Segundos depois de um kernel panic até a máquina reiniciar sozinha; 0 espera para sempre na tela do panic.
## Quando mudar
Um roteador deve voltar sozinho: 10 s dão tempo de ler o panic num console.
## Cuidado
Com 0, um roteador remoto fica parado até alguém chegar nele."##,
    ),
    (
        "tuning.kernel.panic_on_oops",
        r##"## O que faz
Transforma um oops do kernel (um bug do qual o kernel sobreviveu, talvez meio quebrado) em panic, para o `kernel.panic` reiniciar a máquina.
## Quando mudar
Num roteador um reinício limpo é melhor que encaminhar com o kernel danificado.
## Cuidado
Um driver que dá oops na partida cria um ciclo de reinícios; a imagem A/B volta para a anterior."##,
    ),
    (
        "tuning.net.core.dev_weight",
        r##"## O que faz
Pacotes que o backlog de uma CPU (RPS, drivers sem NAPI) pode tratar por vez dentro de uma rodada do softirq. Drivers NAPI usam o próprio peso (64).
## Quando mudar
Raramente: só com RPS em placa de fila única e `time_squeeze` que o budget não resolveu.
## Cuidado
Não muda as filas da placa em drivers NAPI; a maioria dos roteadores nunca mexe nele."##,
    ),
    (
        "tuning.net.core.netdev_budget",
        r##"## O que faz
Quantos pacotes uma rodada do softirq de recepção trata, somando todas as filas da CPU, antes de ceder a vez.
## Quando aumentar
Quando o `time_squeeze` cresce (aba Resumo): a rodada termina com trabalho sobrando e o resto espera a próxima. 600 é um valor comum em roteador; 1000 ou mais para portas de 10/40 Gb/s.
## Cuidado
Uma rodada mais longa atrasa todo o resto naquela CPU (programas, o daemon de roteamento). Aumente junto com o `netdev_budget_usecs`."##,
    ),
    (
        "tuning.net.core.netdev_budget_usecs",
        r##"## O que faz
O limite de tempo de uma rodada do softirq de recepção, em microssegundos: a rodada termina no budget ou neste tempo, o que vier antes.
## Quando aumentar
Junto com o `netdev_budget`, quando o `time_squeeze` cresce. O padrão do kernel depende do HZ (2000 µs com HZ=1000, 8000 µs com HZ=250).
## Cuidado
O perfil de baixa latência o mantém curto de propósito: uma rodada longa faz o resto da CPU esperar."##,
    ),
    (
        "tuning.net.core.netdev_max_backlog",
        r##"## O que faz
Pacotes que cada CPU pode guardar esperando o softirq de recepção quando chegam mais rápido do que ele consegue tratar (RPS, veth, túneis e drivers sem NAPI enfileiram aqui).
## Quando aumentar
Quando o `softnet_stat` conta descartes (a aba Resumo avisa) ou as portas são de 10 Gb/s ou mais: uma rajada espera em vez de ser descartada.
## Cuidado
Uma fila enorme só esconde uma CPU que não dá conta e acrescenta atraso (bufferbloat). Aumente o budget antes."##,
    ),
    (
        "tuning.net.core.rmem_max",
        r##"## O que faz
O maior buffer de recepção que um socket do próprio roteador pode pedir. **Só plano de controle**: pacotes encaminhados nunca passam por buffers de socket.
## Quando aumentar
BGP com tabelas completas e route reflectors: o daemon pede buffers grandes para uma rajada de updates não travar a sessão.
## Cuidado
É um teto, não um padrão: a memória só é usada pelos sockets que pedem."##,
    ),
    (
        "tuning.net.core.somaxconn",
        r##"## O que faz
A maior fila de conexões esperando um serviço do roteador (API, BGP, web) aceitá-las. **Só plano de controle.**
## Quando mudar
Raramente: 4096 é o padrão do kernel desde o 5.4.
## Cuidado
Não afeta o tráfego encaminhado."##,
    ),
    (
        "tuning.net.core.wmem_max",
        r##"## O que faz
O maior buffer de envio que um socket do próprio roteador pode pedir. **Só plano de controle**: pacotes encaminhados nunca passam por buffers de socket.
## Quando aumentar
BGP com tabelas completas e route reflectors: o daemon pede buffers grandes para uma rajada de updates não travar a sessão.
## Cuidado
É um teto, não um padrão: a memória só é usada pelos sockets que pedem."##,
    ),
    (
        "tuning.net.ipv4.conf.all.rp_filter",
        r##"## O que faz
Filtro de caminho reverso: confere o endereço de origem de cada pacote na tabela de rotas. Estrito (1) descarta se a rota de volta não sai pela mesma interface; solto (2), só se não houver rota de volta nenhuma. O kernel usa o maior entre o `all` e o valor da interface.
## Quando mudar
Solto é a escolha segura num roteador de provedor: descarta origem falsa e mantém o roteamento assimétrico (dois links, BGP com vários upstreams) funcionando. Desligado economiza uma consulta de rota por pacote quando o anti-spoofing é feito no firewall.
## Cuidado
Estrito quebra o roteamento assimétrico em silêncio: a resposta entra por outro link e é descartada. O padrão do MikroTik é desligado."##,
    ),
    (
        "tuning.net.ipv4.conf.default.rp_filter",
        r##"## O que faz
O filtro de caminho reverso que uma interface recebe ao ser criada (uma VLAN, bond ou túnel novo). O kernel usa o maior entre o `all` e o valor da própria interface, então desligar o `all` não muda nada numa interface criada com estrito.
## Quando mudar
Junto com o `net.ipv4.conf.all.rp_filter`, para o mesmo valor.
## Cuidado
Interfaces que já existem mantêm o próprio valor (ajustes por interface: G1.26b)."##,
    ),
    (
        "tuning.net.ipv4.fib_multipath_hash_policy",
        r##"## O que faz
Como o tráfego IPv4 é dividido entre rotas de mesmo custo (ECMP): camada 3 usa só os endereços, camada 4 soma protocolo e portas, camada 3 interna olha dentro de túneis.
## Quando mudar
Camada 4 espalha muitos fluxos entre os mesmos dois hosts (um pool de CGNAT falando com uma CDN) por todos os caminhos; camada 3 manda todos por um só.
## Cuidado
Os pacotes de um mesmo fluxo seguem sempre pelo mesmo caminho nos dois casos; só fragmentos podem divergir com camada 4."##,
    ),
    (
        "tuning.net.ipv4.ip_forward",
        r##"## O que faz
Se o kernel encaminha pacotes IPv4 entre interfaces. Um roteador precisa dele ligado; desligado, a máquina só responde por si.
## Quando mudar
Nunca num roteador. Desligado é para um host.
## Cuidado
Desligar para todo o roteamento IPv4 na hora. Ligar também desliga o LRO de todas as portas (o kernel faz isso)."##,
    ),
    (
        "tuning.net.ipv4.neigh.default.gc_thresh1",
        r##"## O que faz
Abaixo desta quantidade de vizinhos IPv4 (ARP) o coletor de lixo não mexe na tabela.
## Quando aumentar
Com muitos hosts nas LANs (um /22 de assinantes, uma VLAN grande): com a tabela cheia, vizinhos novos são recusados ("neighbour table overflow") e hosts perdem conexão. A aba Resumo conta os estouros.
## Cuidado
Mantenha gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; cada entrada custa algumas centenas de bytes. No MikroTik o limite se chama `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv4.neigh.default.gc_thresh2",
        r##"## O que faz
Acima desta quantidade de entradas IPv4 (ARP) o coletor remove as velhas em até 5 segundos.
## Quando aumentar
Com muitos hosts nas LANs (um /22 de assinantes, uma VLAN grande): com a tabela cheia, vizinhos novos são recusados ("neighbour table overflow") e hosts perdem conexão. A aba Resumo conta os estouros.
## Cuidado
Mantenha gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; cada entrada custa algumas centenas de bytes. No MikroTik o limite se chama `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv4.neigh.default.gc_thresh3",
        r##"## O que faz
O máximo de vizinhos IPv4 (ARP) que a tabela guarda: o limite rígido.
## Quando aumentar
Com muitos hosts nas LANs (um /22 de assinantes, uma VLAN grande): com a tabela cheia, vizinhos novos são recusados ("neighbour table overflow") e hosts perdem conexão. A aba Resumo conta os estouros.
## Cuidado
Mantenha gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; cada entrada custa algumas centenas de bytes. No MikroTik o limite se chama `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv4.route.max_size",
        r##"## O que faz
Nada desde o Linux 3.6: o cache de rotas IPv4 que ele limitava não existe mais. O kernel o mantém por causa de scripts antigos.
## Quando mudar
Nunca: uma tabela BGP completa não precisa de nada aqui.
## Cuidado
Os guias que ainda mandam aumentá-lo são de antes de 2012."##,
    ),
    (
        "tuning.net.ipv4.tcp_max_syn_backlog",
        r##"## O que faz
Conexões meio abertas com os serviços do próprio roteador que o kernel lembra. **Só plano de controle.**
## Quando mudar
Aumente quando a API ou a porta BGP do roteador sofrem carga de SYN e os cookies estão desligados.
## Cuidado
Não afeta o tráfego encaminhado."##,
    ),
    (
        "tuning.net.ipv4.tcp_syncookies",
        r##"## O que faz
Responde a uma inundação de SYN contra os serviços do próprio roteador com cookies em vez de entradas na fila. **Só plano de controle**: uma inundação que só passa pelo roteador é assunto do firewall.
## Quando mudar
Deixe "quando precisar" (1): os cookies só entram com a fila cheia.
## Cuidado
"Sempre" (2) desliga algumas opções do TCP em toda conexão ao roteador."##,
    ),
    (
        "tuning.net.ipv6.conf.all.forwarding",
        r##"## O que faz
Se o kernel encaminha pacotes IPv6. Ligado, as interfaces também deixam de aceitar Router Advertisements, a não ser com `accept_ra` = 2 (o CoreRouter põe isso onde um cliente DHCPv6 precisa).
## Quando mudar
Nunca num roteador que roteia IPv6.
## Cuidado
Desligado, o roteamento IPv6 para na hora."##,
    ),
    (
        "tuning.net.ipv6.fib_multipath_hash_policy",
        r##"## O que faz
O mesmo da opção IPv4, para rotas IPv6 de mesmo custo: camada 3 (endereços e flow label), camada 4 (soma as portas), camada 3 interna.
## Quando mudar
Camada 4 quando vários caminhos levam tráfego entre poucos hosts.
## Cuidado
Deixe IPv4 e IPv6 iguais, senão as duas famílias carregam os links de modo diferente."##,
    ),
    (
        "tuning.net.ipv6.neigh.default.gc_thresh1",
        r##"## O que faz
Abaixo desta quantidade de vizinhos IPv6 (NDP) o coletor de lixo não mexe na tabela.
## Quando aumentar
Com muitos hosts nas LANs (um /22 de assinantes, uma VLAN grande): com a tabela cheia, vizinhos novos são recusados ("neighbour table overflow") e hosts perdem conexão. A aba Resumo conta os estouros.
## Cuidado
Mantenha gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; cada entrada custa algumas centenas de bytes. No MikroTik o limite se chama `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv6.neigh.default.gc_thresh2",
        r##"## O que faz
Acima desta quantidade de entradas IPv6 (NDP) o coletor remove as velhas em até 5 segundos.
## Quando aumentar
Com muitos hosts nas LANs (um /22 de assinantes, uma VLAN grande): com a tabela cheia, vizinhos novos são recusados ("neighbour table overflow") e hosts perdem conexão. A aba Resumo conta os estouros.
## Cuidado
Mantenha gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; cada entrada custa algumas centenas de bytes. No MikroTik o limite se chama `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv6.neigh.default.gc_thresh3",
        r##"## O que faz
O máximo de vizinhos IPv6 (NDP) que a tabela guarda: o limite rígido.
## Quando aumentar
Com muitos hosts nas LANs (um /22 de assinantes, uma VLAN grande): com a tabela cheia, vizinhos novos são recusados ("neighbour table overflow") e hosts perdem conexão. A aba Resumo conta os estouros.
## Cuidado
Mantenha gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; cada entrada custa algumas centenas de bytes. No MikroTik o limite se chama `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv6.route.max_size",
        r##"## O que faz
Antes do Linux 6.3, o máximo de rotas IPv6 que o kernel aceitava (padrão 4096): uma tabela IPv6 completa (mais de 200 000 rotas) não instalava. Desde o 6.3 não limita mais.
## Quando aumentar
Num kernel anterior ao 6.3 que recebe a tabela IPv6 completa: 1048576 dá folga.
## Cuidado
Desde o Linux 6.3 mudar não faz nada."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_buckets",
        r##"## O que faz
O tamanho da tabela hash do conntrack. Cada busca percorre a corrente de um bucket: com o `nf_conntrack_max` quatro vezes os buckets, as correntes têm quatro entradas em média.
## Quando aumentar
Junto com o `nf_conntrack_max`; o kernel o calcula pela RAM no boot e não acompanha mudanças posteriores do máximo.
## Cuidado
Mudar reconstrói a tabela com o tráfego passando (um pico curto de CPU). Só o primeiro namespace de rede do host pode mudar."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_generic_timeout",
        r##"## O que faz
Segundos que um fluxo de outro protocolo (GRE, ESP, SCTP sem o módulo) fica.
## Quando mudar
Menor em CGNAT; maior só para túneis ociosos sem keepalive.
## Cuidado
Curto demais derruba túneis IPsec e GRE que ficam em silêncio."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_icmp_timeout",
        r##"## O que faz
Segundos que uma consulta ICMP (ping) fica na tabela.
## Quando mudar
A RFC 5508 REQ-1 pede que o NAT a mantenha por pelo menos 60 s; os 30 s do kernel ficam abaixo.
## Cuidado
Cada ping pelo CGNAT segura um identificador: tempos muito longos os esgotam em pools cheios."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_max",
        r##"## O que faz
O máximo de conexões que o rastreador guarda: NAT, CGNAT e toda regra de firewall com estado precisam de uma entrada por fluxo. Tabela cheia descarta conexões novas ("table full, dropping packet" no log do kernel).
## Quando aumentar
Em CGNAT e NAT movimentado: cada assinante mantém centenas de fluxos. A aba Resumo avisa com 80 % de ocupação.
## Cuidado
Cada entrada custa ~320 B de RAM que o kernel não devolve: 4 milhões de entradas são ~1,3 GiB. O limite aqui é um quarto da RAM."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_close_wait",
        r##"## O que faz
Segundos que uma conexão TCP fica depois que o outro lado fechou.
## Quando mudar
Raramente.
## Cuidado
Como o `fin_wait`."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_established",
        r##"## O que faz
Segundos que uma conexão TCP estabelecida fica na tabela sem nenhum pacote. O padrão do kernel é 5 dias.
## Quando mudar
Menor em CGNAT: um cliente que sumiu deixa a entrada (e a porta pública) por dias. O MikroTik usa 1 dia.
## Cuidado
RFC 5382 REQ-5: nunca menos de 2 h 4 min (7440 s), senão sessões SSH e de banco de dados ociosas caem."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
        r##"## O que faz
Segundos que uma conexão TCP fechando fica depois do primeiro FIN.
## Quando mudar
Menor libera portas do CGNAT antes em pools muito cheios.
## Cuidado
Abaixo de um minuto, pacotes atrasados de uma conexão fechando podem ser descartados como inválidos."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_syn_recv",
        r##"## O que faz
Segundos que uma conexão TCP espera o ACK final do handshake.
## Quando mudar
Raramente, como o `syn_sent`.
## Cuidado
Curto demais derruba handshakes lentos em satélite ou links congestionados."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_syn_sent",
        r##"## O que faz
Segundos que uma conexão TCP espera a resposta do seu SYN.
## Quando mudar
Raramente: menor só quando inundações de SYN enchem a tabela.
## Cuidado
A RFC 5382 REQ-5 pede pelo menos 4 minutos para conexões abrindo ou fechando; os 120 s do kernel já ficam abaixo."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_time_wait",
        r##"## O que faz
Segundos que uma conexão TCP fechada fica, para pegar pacotes atrasados.
## Quando mudar
Menor em pools de CGNAT que ficam sem portas (o MikroTik usa 10 s).
## Cuidado
Muito curto deixa uma conexão nova reusar a porta enquanto pacotes antigos ainda viajam."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_udp_timeout",
        r##"## O que faz
Segundos que um fluxo UDP que ainda não teve resposta fica (consultas DNS, varreduras).
## Quando mudar
Menor em CGNAT: cada consulta sem resposta segura uma porta pública (MikroTik: 10 s).
## Cuidado
Abaixo de 10 s uma resposta DNS lenta pode não achar a entrada."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_udp_timeout_stream",
        r##"## O que faz
Segundos que um fluxo UDP com resposta (VoIP, jogos, QUIC, VPN) fica sem nenhum pacote.
## Quando mudar
Maior mantém VoIP e VPN atrás do NAT sem keepalive (MikroTik: 3 min).
## Cuidado
RFC 4787 REQ-5: um mapeamento de NAT deve durar pelo menos 2 minutos (5 recomendados)."##,
    ),
    (
        "tuning.profiles",
        r##"## Perfis
Cada perfil é calculado para esta máquina (RAM, CPUs, velocidade das portas), não copiado de uma tabela:
- **Conservador**: só o que é seguro em qualquer lugar (encaminhamento ligado, ECMP por camada 4, reinício no panic); o resto fica como o kernel tem.
- **Balanceado**: um roteador com NAT: budget e backlog de recepção maiores, conntrack com 1/16 da RAM, tempos que liberam portas do CGNAT antes, tabelas de vizinhos para LANs grandes.
- **Alto desempenho**: mais de tudo para 10/40/100 Gb/s e CGNAT: conntrack com 1/8 da RAM, os menores tempos que as RFCs permitem.
- **Baixa latência**: rodadas de recepção curtas e backlog pequeno, para o pacote esperar menos.
## Plano de controle
As opções de TCP (buffers de socket, SYN cookies) só afetam as conexões do próprio roteador (BGP, a API), nunca o tráfego encaminhado.
## Aplicar
"Aplicar com Safe Mode" entra em Safe Mode antes: se a conexão com o roteador cair, toda mudança volta."##,
    ),
    (
        "tuning.vm.min_free_kbytes",
        r##"## O que faz
Memória que o kernel mantém livre para alocações que não podem esperar, como a placa repondo o anel de RX dentro de uma interrupção.
## Quando aumentar
Com anéis grandes e portas de 10 Gb/s ou mais: quando falta, o driver não repõe o anel e descarta pacotes ("page allocation failure" no log).
## Cuidado
Essa memória fica indisponível para os programas; mais de 5 % da RAM raramente ajuda. O limite aqui é um décimo dela."##,
    ),
];

/// Labels by their English text.
pub(super) const LABELS: &[(&str, &str)] = &[
    (
        "Apply with Safe Mode",
        r##"Aplicar com Safe Mode"##,
    ),
    (
        "Balanced",
        r##"Balanceado"##,
    ),
    (
        "Boot parameters of the image (isolcpus, nohz_full, C-states, IOMMU, mitigations) arrive with G1.26d.",
        r##"Os parâmetros de boot da imagem (isolcpus, nohz_full, C-states, IOMMU, mitigations) chegam com o G1.26d."##,
    ),
    (
        "CPU and IRQ",
        r##"CPU e IRQ"##,
    ),
    (
        "Click a parameter to change it.",
        r##"Clique num parâmetro para mudá-lo."##,
    ),
    (
        "Configured",
        r##"Configurado"##,
    ),
    (
        "Connection tracking",
        r##"Rastreamento de conexões"##,
    ),
    (
        "Conservative",
        r##"Conservador"##,
    ),
    (
        "Control plane (TCP)",
        r##"Plano de controle (TCP)"##,
    ),
    (
        "Current",
        r##"Atual"##,
    ),
    (
        "Diagnosis",
        r##"Diagnóstico"##,
    ),
    (
        "Equivalent command",
        r##"Comando equivalente"##,
    ),
    (
        "Find",
        r##"Buscar"##,
    ),
    (
        "High throughput",
        r##"Alto desempenho"##,
    ),
    (
        "Interrupt affinity per NUMA node, RPS/XPS, the CPU governor and C-states arrive with G1.26c.",
        r##"A afinidade das interrupções por nó NUMA, RPS/XPS, o governor da CPU e os C-states chegam com o G1.26c."##,
    ),
    (
        "Low latency",
        r##"Baixa latência"##,
    ),
    (
        "Memory",
        r##"Memória"##,
    ),
    (
        "NUMA nodes",
        r##"Nós NUMA"##,
    ),
    (
        "Neighbor tables",
        r##"Tabelas de vizinhos"##,
    ),
    (
        "Not in this kernel or network namespace (conntrack: not loaded yet).",
        r##"Não existe neste kernel ou namespace de rede (conntrack: ainda não carregado)."##,
    ),
    (
        "Not set: the kernel's own value is in use",
        r##"Não definido: vale o valor do próprio kernel"##,
    ),
    (
        "Nothing to change",
        r##"Nada a mudar"##,
    ),
    (
        "Nothing to report: the counters look healthy.",
        r##"Nada a relatar: os contadores estão saudáveis."##,
    ),
    (
        "Packet receive",
        r##"Recepção de pacotes"##,
    ),
    (
        "Parameter",
        r##"Parâmetro"##,
    ),
    (
        "Port",
        r##"Porta"##,
    ),
    (
        "Profile",
        r##"Perfil"##,
    ),
    (
        "Profiles",
        r##"Perfis"##,
    ),
    (
        "Queues",
        r##"Filas"##,
    ),
    (
        "RX missed",
        r##"RX perdidos"##,
    ),
    (
        "RX ring",
        r##"Anel RX"##,
    ),
    (
        "Range",
        r##"Faixa"##,
    ),
    (
        "Recommended",
        r##"Recomendado"##,
    ),
    (
        "Recommended here",
        r##"Recomendado aqui"##,
    ),
    (
        "Rings, queues, RSS, interrupt coalescing, offloads, flow control and txqueuelen per port arrive with G1.26b.",
        r##"Anéis, filas, RSS, coalescência de interrupções, offloads, controle de fluxo e txqueuelen por porta chegam com o G1.26b."##,
    ),
    (
        "Routing",
        r##"Roteamento"##,
    ),
    (
        "Safe Mode is held by",
        r##"O Safe Mode está com"##,
    ),
    (
        "Safe Mode: confirm with the Safe Mode button on the top bar; if the connection drops, every change goes back.",
        r##"Safe Mode: confirme no botão Safe Mode da barra de cima; se a conexão cair, toda mudança volta."##,
    ),
    (
        "Saving…",
        r##"Salvando…"##,
    ),
    (
        "Set",
        r##"Definir"##,
    ),
    (
        "Show differences",
        r##"Ver diferenças"##,
    ),
    (
        "Speed",
        r##"Velocidade"##,
    ),
    (
        "Stability",
        r##"Estabilidade"##,
    ),
    (
        "Summary",
        r##"Resumo"##,
    ),
    (
        "TX ring",
        r##"Anel TX"##,
    ),
    (
        "The four profiles for this machine, side by side. The profile picked at the top is the one Summary applies.",
        r##"Os quatro perfis para esta máquina, lado a lado. O perfil escolhido no alto é o que o Resumo aplica."##,
    ),
    (
        "This backend does not describe the machine: ranges come from the kernel only.",
        r##"Este backend não descreve a máquina: as faixas vêm só do kernel."##,
    ),
    (
        "This router has no System › Tuning yet: update corerouter-daemon.",
        r##"Este roteador ainda não tem System › Tuning: atualize o corerouter-daemon."##,
    ),
    (
        "Tuning",
        r##"Ajuste fino"##,
    ),
    (
        "Type a whole number",
        r##"Digite um número inteiro"##,
    ),
    (
        "Unset",
        r##"Remover"##,
    ),
    (
        "Use recommended",
        r##"Usar o recomendado"##,
    ),
    (
        "Value",
        r##"Valor"##,
    ),
    (
        "Why",
        r##"Motivo"##,
    ),
    (
        "control plane",
        r##"plano de controle"##,
    ),
    (
        "critical",
        r##"crítico"##,
    ),
    (
        "differs",
        r##"difere"##,
    ),
    (
        "flaps link",
        r##"pisca o link"##,
    ),
    (
        "needs reboot",
        r##"pede reboot"##,
    ),
    (
        "not applied",
        r##"não aplicado"##,
    ),
    (
        "obsolete",
        r##"obsoleto"##,
    ),
    (
        "parameters differ from this profile.",
        r##"parâmetros diferem deste perfil."##,
    ),
    (
        "waiting for the router…",
        r##"esperando o roteador…"##,
    ),
    (
        "warning",
        r##"aviso"##,
    ),
];

/// The engine's reasons (`why.<id>`) and findings (`finding.<id>`); English comes
/// from the engine itself.
pub(super) const TEMPLATES: &[(&str, &str)] = &[
    (
        "finding.conntrack_full",
        r##"A tabela do conntrack está {pct}% cheia ({count} de {max}): conexões novas são descartadas quando ela enche."##,
    ),
    (
        "finding.forwarding_off",
        r##"O encaminhamento IPv4 está desligado: este roteador não roteia."##,
    ),
    (
        "finding.neigh_full",
        r##"A tabela de vizinhos {family} estourou {count} vezes desde o boot: hosts perdem conexão."##,
    ),
    (
        "finding.nic_missed",
        r##"{nics} descartaram {count} quadros por falta de descritores de RX, com o anel de RX abaixo do máximo (aba Interfaces)."##,
    ),
    (
        "finding.softnet_dropped",
        r##"{count} pacotes descartados desde o boot: o backlog estava cheio (CPU {cpu} a que mais)."##,
    ),
    (
        "finding.softnet_squeeze",
        r##"O softirq de recepção ficou sem budget {count} vezes desde o boot ({ratio} dos pacotes; CPU {cpu} a que mais)."##,
    ),
    (
        "why.backlog",
        r##"Dimensionado para {gbps} Gb/s de portas: uma rajada espera no backlog em vez de ser descartada."##,
    ),
    (
        "why.budget",
        r##"Mais pacotes por rodada de recepção ({profile}): menos squeezes sob carga."##,
    ),
    (
        "why.budget_low",
        r##"O valor do kernel: rodadas de recepção curtas, menos espera ({profile})."##,
    ),
    (
        "why.ct_buckets",
        r##"Um quarto do nf_conntrack_max: correntes curtas em cada busca."##,
    ),
    (
        "why.ct_max",
        r##"{share} da RAM ({mem}) para o rastreamento de conexões, ~320 B por entrada."##,
    ),
    (
        "why.ct_timeout",
        r##"{value} s ({profile}): conexões mortas saem da tabela antes."##,
    ),
    (
        "why.ct_timeout_rfc",
        r##"{value} s ({profile}): conexões mortas saem da tabela antes, dentro da {rfc}."##,
    ),
    (
        "why.default",
        r##"O padrão do kernel."##,
    ),
    (
        "why.forward",
        r##"Um roteador encaminha pacotes."##,
    ),
    (
        "why.hash_l4",
        r##"Espalha os fluxos pelas rotas de mesmo custo também pela porta, não só pelo endereço."##,
    ),
    (
        "why.keep",
        r##"O perfil {profile} mantém o valor do kernel."##,
    ),
    (
        "why.min_free",
        r##"Uma reserva para alocações em interrupção (anéis da placa): {share} da RAM."##,
    ),
    (
        "why.neigh",
        r##"{entries} vizinhos para {mem} de RAM; os outros limites em 1/2 e 1/8 disso."##,
    ),
    (
        "why.oops",
        r##"Um oops deixa o kernel em dúvida sobre si mesmo: trate como panic e reinicie."##,
    ),
    (
        "why.panic",
        r##"Reiniciar 10 s depois de um kernel panic em vez de ficar parado."##,
    ),
    (
        "why.rp_loose",
        r##"Solto: descarta origens sem rota nenhuma e mantém o roteamento assimétrico (vários links) funcionando."##,
    ),
    (
        "why.rp_off",
        r##"Desligado: nenhuma consulta de rota extra por pacote; filtre origens falsas no firewall."##,
    ),
    (
        "why.sockbuf",
        r##"Deixa o BGP e a API pedirem buffers de socket de 16 MiB (tabelas completas)."##,
    ),
    (
        "why.v6_routes",
        r##"O Linux {kernel} ainda limita as rotas IPv6 ao max_size: espaço para a tabela completa."##,
    ),
];
