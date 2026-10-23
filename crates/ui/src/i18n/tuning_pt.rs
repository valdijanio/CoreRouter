//! Portuguese explanations, labels and reason templates of System ›
//! Tuning (G1.26), each sorted by key.

/// Explanations by key (`tuning.<parameter>`, `tuning.<topic>`).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "tuning.boot",
        r##"## Parâmetros de boot
Vão na linha de comando do kernel da imagem do roteador e valem a partir do **próximo boot**. A imagem é imutável e A/B: um boot que falha volta sozinho para a imagem anterior, com a linha de comando dela.
## Hoje
A imagem A/B (G1.6) ainda não existe: os parâmetros ficam gravados na config e aparecem como pendentes; a imagem vai lê-los quando existir (G1.26h). "Running" é o que este boot usou (`/proc/cmdline`)."##,
    ),
    (
        "tuning.boot.intel_idle.max_cstate",
        r##"## O que faz
O C-state mais profundo que o driver de ociosidade intel_idle pode usar, desde o boot: 0 desliga esse driver, 1 mantém as CPUs em C1. Vale a partir do próximo boot.
## Quando mudar
Menor latência num hardware em que o limite de C-state da aba CPU (PM QoS, sem reboot) não basta.
## Cuidado
Mais consumo e calor. O `cpu_dma_latency` da aba CPU faz o mesmo em tempo de execução e some se o daemon parar: prefira-o."##,
    ),
    (
        "tuning.boot.iommu",
        r##"## O que faz
**pt** (passthrough): os dispositivos do host fazem DMA sem a tradução do IOMMU, e os dispositivos entregues a VMs (VFIO, SR-IOV) continuam com ela. **off** desliga o IOMMU; **nopt** traduz tudo.
## Quando mudar
pt num roteador com o IOMMU ligado: sem isso, o mapeamento de DMA de cada pacote custa CPU.
## Cuidado
off perde a proteção contra um dispositivo escrevendo onde não deve (ataques por DMA) e quebra o VFIO."##,
    ),
    (
        "tuning.boot.isolcpus",
        r##"## O que faz
Tira estas CPUs do escalonador desde o boot: nenhuma tarefa comum roda ali, a não ser fixada. Vale a partir do **próximo boot**.
## Quando mudar
Raramente num roteador com o kernel: o encaminhamento roda em softirq na CPU da IRQ de cada fila, que o isolcpus não move. Ajuda um plano de dados em busy polling (DPDK, AF_XDP) que é dono de CPUs inteiras.
## Cuidado
O escalonador não volta a usá-las até um reboot (a documentação do kernel prefere cpusets para o que é dinâmico). A CPU 0 fica com o sistema."##,
    ),
    (
        "tuning.boot.mitigations",
        r##"## O que faz
As defesas do kernel contra canais laterais da CPU (Spectre, Meltdown, MDS, Retbleed…). **auto** (padrão) as mantém; **auto,nosmt** também desliga o hyper-threading onde precisa; **off** tira todas.
## Quando mudar
off ganha alguns por cento só numa máquina que não roda nada além do próprio código.
## Cuidado
**Risco de segurança.** Um roteador ainda trata entrada hostil: a API, a web, o BGP e o DNS de fora. Com off, uma falha em qualquer um deles pode ler a memória de todos os outros processos, chaves inclusive. O CoreRouter pede confirmação explícita e nunca o recomenda."##,
    ),
    (
        "tuning.boot.nohz_full",
        r##"## O que faz
Para o tick periódico do temporizador nestas CPUs enquanto rodam uma única tarefa (e tira delas os callbacks de RCU). Vale a partir do próximo boot.
## Quando mudar
Junto com o isolcpus, em CPUs que fazem busy polling de pacotes: nenhum tick as interrompe.
## Cuidado
Precisa de um kernel com NO_HZ_FULL. A CPU de boot não pode estar na lista. Sem uma única tarefa ocupada por CPU, só acrescenta custo."##,
    ),
    (
        "tuning.boot.pcie_aspm",
        r##"## O que faz
Active State Power Management do PCIe. **off**: o kernel deixa o ASPM como o firmware o deixou e não o liga; **force**: liga mesmo onde o firmware proíbe.
## Quando mudar
off num roteador: uma placa cujo link PCIe dorme acrescenta microssegundos aos primeiros pacotes depois de uma pausa.
## Cuidado
force pode travar máquinas cujos dispositivos não suportam bem o ASPM."##,
    ),
    (
        "tuning.boot.processor.max_cstate",
        r##"## O que faz
O C-state mais profundo que o driver de ociosidade ACPI (processor) pode usar, desde o boot: 0 desliga esse driver, 1 mantém as CPUs em C1. Vale a partir do próximo boot.
## Quando mudar
Menor latência num hardware em que o limite de C-state da aba CPU (PM QoS, sem reboot) não basta.
## Cuidado
Mais consumo e calor. O `cpu_dma_latency` da aba CPU faz o mesmo em tempo de execução e some se o daemon parar: prefira-o."##,
    ),
    (
        "tuning.cpu.cpu_dma_latency",
        r##"## O que faz
O C-state mais profundo em que as CPUs podem dormir, dado como a latência de despertar permitida em µs: uma requisição PM QoS em `/dev/cpu_dma_latency`. 1 µs as mantém em C1; 0 as faz ficar em polling (nunca dormem). Sem valor: a escolha do próprio kernel.
## Quando mudar
Baixa latência: C-states profundos levam de dezenas a centenas de µs para acordar, e os primeiros pacotes de uma rajada esperam por isso. **Não precisa de reboot**, ao contrário do `intel_idle.max_cstate` (aba Boot).
## Cuidado
A requisição vale enquanto o arquivo fica aberto: o daemon a segura, então se o daemon parar o limite some (falha segura). C-states rasos gastam energia; 0 (polling) queima núcleos inteiros."##,
    ),
    (
        "tuning.cpu.governor",
        r##"## O que faz
O governor do cpufreq de cada política de CPU: como o kernel escolhe o clock. **performance** o mantém no máximo; schedutil e ondemand seguem a carga; powersave o mantém baixo.
## Quando mudar
performance num roteador: a carga de softirq chega em rajadas, e subir o clock leva milissegundos, o bastante para descartar pacotes com o anel cheio (o tuned e o VyOS fazem o mesmo).
## Cuidado
Mais consumo e calor. Sem cpufreq (muitas VMs, alguns ajustes de firmware) a linha fica vazia: o clock não é o kernel quem escolhe."##,
    ),
    (
        "tuning.cpu.hw_watchdog",
        r##"## O que faz
O watchdog de hardware (`/dev/watchdog`): o daemon o alimenta a cada segundo; se parar (travado, morto, kernel preso) a placa reinicia sozinha.
## Quando mudar
Ligado num roteador onde ninguém chega em pessoa. Junto com o `kernel.panic` ele traz a máquina de volta de qualquer travamento.
## Cuidado
Desligar envia o fechamento mágico, que para o temporizador. Um driver sem fechamento mágico continua contando depois que o CoreRouter solta: reinicia, a menos que outra coisa o alimente."##,
    ),
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
Uma rodada mais longa atrasa todo o resto naquela CPU (programas, o daemon de roteamento). Aumente junto com o `netdev_budget_usecs`.
Vale para o host todo: um container ou um namespace de rede não o tem (aparece como –)."##,
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
Estrito quebra o roteamento assimétrico em silêncio: a resposta entra por outro link e é descartada. O padrão do MikroTik é desligado.
## Medido
Encaminhando UDP de 64 bytes numa CPU (veth num namespace): estrito 1,61 Mpps, desligado 1,82 Mpps (+13 %). Desligar o `all` não basta: o valor da própria interface (e o `default`, para as novas) também precisa baixar."##,
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
Desligar para todo o roteamento IPv4 na hora. Ligar também desliga o LRO de todas as portas (o kernel faz isso).
Mudá-lo reinicia outros parâmetros de configuração para o padrão de host ou de roteador (`ip-sysctl.rst`): o CoreRouter sempre o grava antes dos outros."##,
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
        "tuning.port.adaptive_rx",
        r##"## O que faz
Coalescência adaptativa de interrupções na recepção: o driver espera mais entre interrupções com tráfego pesado e dispara logo com tráfego leve (ITR da Intel, DIM da Mellanox).
## Quando mudar
Ligada na maioria dos roteadores. Desligada, com `rx_usecs` = 0, para a menor latência (uma interrupção por pacote).
## Cuidado
Desligada com `rx_usecs` alto atrasa cada pacote; desligada com 0 pode gastar uma CPU inteira em interrupções a plena taxa."##,
    ),
    (
        "tuning.port.adaptive_tx",
        r##"## O que faz
Coalescência adaptativa de interrupções na transmissão: o driver espera mais entre interrupções com tráfego pesado e dispara logo com tráfego leve (ITR da Intel, DIM da Mellanox).
## Quando mudar
Ligada na maioria dos roteadores. Desligada, com `tx_usecs` = 0, para a menor latência (uma interrupção por pacote).
## Cuidado
Desligada com `tx_usecs` alto atrasa cada pacote; desligada com 0 pode gastar uma CPU inteira em interrupções a plena taxa."##,
    ),
    (
        "tuning.port.combined_channels",
        r##"## O que faz
Pares de filas (recepção e transmissão juntas) que a porta usa. Cada fila tem a própria interrupção, atendida por uma CPU: mais filas espalham o trabalho de recepção (o RSS manda cada fluxo para uma fila).
## Quando mudar
Uma fila por CPU do nó NUMA da porta (`scaling.rst`): uma CPU do outro nó chega à placa atravessando a interconexão. Mais filas que CPUs só acrescentam interrupções.
## Cuidado
Mudar **reinicia a porta** (o link cai por um instante) e move as interrupções: a afinidade de CPU e IRQ vem no G1.26c."##,
    ),
    (
        "tuning.port.gro",
        r##"## O que faz
Generic Receive Offload: o kernel junta pacotes seguidos de um fluxo num só antes de roteá-los e os separa de novo no envio. Menos custo por pacote.
## Quando mudar
Deixe ligado: ele é reversível, então é seguro para roteamento e bridge (ao contrário do LRO).
## Cuidado
Desligue só para depurar capturas de pacotes."##,
    ),
    (
        "tuning.port.gso",
        r##"## O que faz
Generic Segmentation Offload: pacotes TCP grandes que o próprio roteador envia são cortados pela placa (ou no fim da pilha) em vez de pela CPU.
## Quando mudar
Não importa para o tráfego encaminhado, que já chega cortado no MTU do cabo. Deixe como o driver tem.
## Cuidado
Ajuda o TCP do próprio roteador (BGP com tabelas completas, a API); desligar só custa CPU."##,
    ),
    (
        "tuning.port.irq_affinity",
        r##"## O que faz
Onde rodam as interrupções das filas da porta. **local node**: cada IRQ de fila numa CPU própria do nó NUMA da porta (fila 0 na primeira CPU, fila 1 na segunda…), gravado em `/proc/irq/<n>/smp_affinity_list`. **kernel**: todas as CPUs online (o padrão do kernel).
## Quando mudar
Nó local num roteador (o `set_irq_affinity -X local` da Intel, `scaling.rst`): uma fila atendida por uma CPU mantém o cache quente, e uma CPU do outro nó chegaria à placa atravessando a interconexão.
## Cuidado
**Pare o irqbalance** antes: ele move as IRQs a cada 10 s, ignora onde a placa está (muitos firmwares não informam o nó NUMA) e sobrescreve a afinidade manual, então o trabalho troca de CPU e os fluxos chegam fora de ordem. A aba Resumo avisa quando ele roda. Alguns drivers fixam a CPU das suas IRQs (IRQs gerenciadas, a flag `o` do MikroTik): o CoreRouter avisa."##,
    ),
    (
        "tuning.port.lro",
        r##"## O que faz
Large Receive Offload: a placa junta pacotes no hardware e reescreve os cabeçalhos de um jeito que não tem volta.
## Quando mudar
Deixe desligado num roteador: o kernel o desliga sozinho quando o forwarding está ligado. Só um host que termina o tráfego ganha com ele.
## Cuidado
Encaminhar pacotes juntados pelo LRO quebra o PMTU e o TCP do outro lado. O CoreRouter recusa ligá-lo aqui (`interface.ethernet.set force=yes` para uma porta que só termina tráfego)."##,
    ),
    (
        "tuning.port.qdisc",
        r##"## O que faz
A disciplina de fila raiz da porta: como os pacotes esperam para sair.
- **mq**: uma qdisc filha por fila de transmissão (o padrão do kernel em placas de várias filas); sem trava dividida por todas as CPUs.
- **fq_codel**: fila justa com AQM CoDel: pouco atraso, sem bufferbloat (a qdisc filha padrão).
- **fq**: fila justa com pacing, para hosts que enviam TCP.
- **pfifo_fast**: a FIFO antiga de três faixas.
- **noqueue**: sem fila (interfaces virtuais).
## Quando mudar
Uma porta de várias filas fica com mq; uma de fila única recebe fq_codel. Limitação de banda (HTB, CAKE) é outra feature.
## Cuidado
fq_codel na raiz de uma placa de várias filas faz todas as CPUs passarem por uma trava: menos vazão.
## Medido
Numa porta virtual (veth, dummy: `noqueue`), o fq_codel custou 7 % da taxa de encaminhamento (de 1,82 para 1,70 Mpps, uma CPU): o perfil mantém `noqueue` ali."##,
    ),
    (
        "tuning.port.rp_filter",
        r##"## O que faz
O filtro de caminho reverso desta porta. O kernel usa o maior entre o `net.ipv4.conf.all.rp_filter` e este valor: desligar o `all` não muda nada numa porta deixada em estrito.
## Quando mudar
Para o mesmo valor do `all` (o perfil faz isso): solto (2) para um provedor com vários links, desligado (0) com anti-spoofing no firewall.
## Cuidado
Estrito (1) num link de saída descarta respostas que voltam por outro link (roteamento assimétrico).
## Medido
Estrito custou 12 % da taxa de encaminhamento contra desligado (1,61 contra 1,82 Mpps, uma CPU, veth)."##,
    ),
    (
        "tuning.port.rps",
        r##"## O que faz
Receive Packet Steering: o kernel espalha os fluxos recebidos pelas CPUs do nó NUMA da porta em software (`rps_cpus` de cada fila de recepção), como o RSS faz no hardware.
## Quando mudar
Ligado numa porta com uma única fila de recepção (placa antiga, VM, túnel), cuja única IRQ carregaria uma CPU só.
## Cuidado
Desligado quando a placa tem várias filas: o RSS já espalha os fluxos e o RPS só acrescenta um passo (o MikroTik e a documentação do kernel dizem o mesmo)."##,
    ),
    (
        "tuning.port.rx_channels",
        r##"## O que faz
Filas só de recepção que a porta usa (placas sem filas combinadas, veth). Cada fila tem a própria interrupção, atendida por uma CPU: mais filas espalham o trabalho de recepção (o RSS manda cada fluxo para uma fila).
## Quando mudar
Uma fila por CPU do nó NUMA da porta (`scaling.rst`): uma CPU do outro nó chega à placa atravessando a interconexão. Mais filas que CPUs só acrescentam interrupções.
## Cuidado
Mudar **reinicia a porta** (o link cai por um instante) e move as interrupções: a afinidade de CPU e IRQ vem no G1.26c."##,
    ),
    (
        "tuning.port.rx_pause",
        r##"## O que faz
Controle de fluxo 802.3x, recepção: a porta obedece aos quadros de pausa do outro lado e para de enviar.
## Quando mudar
Desligado num roteador (o padrão do ice da Intel): uma pausa para a porta inteira, então um receptor lento atrasa todos os fluxos (bloqueio de cabeça de fila). Descartar sai mais barato que parar; o TCP lida com o descarte.
## Cuidado
Alguns switches e redes de storage dependem da pausa; combine com o outro lado. Mudar pode renegociar o link."##,
    ),
    (
        "tuning.port.rx_ring",
        r##"## O que faz
Descritores no anel de RX da porta: pacotes que a placa guarda para o kernel (recepção) antes de ter de descartar ("missed").
## Quando aumentar
Quando o `rx_missed_errors` cresce (aba Resumo) ou a porta recebe rajadas a 10 Gb/s ou mais. Os guias da Intel e da Mellanox sobem até o máximo para encaminhamento.
## Cuidado
Mudar **reinicia a porta**: o link cai por um instante (use Safe Mode). Um anel maior usa mais memória e deixa uma fila guardar mais atraso numa sobrecarga."##,
    ),
    (
        "tuning.port.rx_usecs",
        r##"## O que faz
Microssegundos que a placa espera depois de um pacote de recepção antes de interromper a CPU (com a coalescência adaptativa desligada). Intel: 80 µs ≈ 12 500 interrupções por segundo por fila.
## Quando mudar
0 para a menor latência; 50–100 para poupar CPU com muitos pacotes por segundo. Com a adaptativa ligada, o driver decide.
## Cuidado
Alguns drivers arredondam (para múltiplos de 2 ou 4 µs); o CoreRouter confere o que o driver guardou."##,
    ),
    (
        "tuning.port.tso",
        r##"## O que faz
TCP Segmentation Offload: pacotes TCP grandes que o próprio roteador envia são cortados pela placa (ou no fim da pilha) em vez de pela CPU.
## Quando mudar
Não importa para o tráfego encaminhado, que já chega cortado no MTU do cabo. Deixe como o driver tem.
## Cuidado
Ajuda o TCP do próprio roteador (BGP com tabelas completas, a API); desligar só custa CPU."##,
    ),
    (
        "tuning.port.tx_channels",
        r##"## O que faz
Filas só de transmissão que a porta usa (placas sem filas combinadas, veth). Cada fila tem a própria interrupção, atendida por uma CPU: mais filas espalham o trabalho de recepção (o RSS manda cada fluxo para uma fila).
## Quando mudar
Uma fila por CPU do nó NUMA da porta (`scaling.rst`): uma CPU do outro nó chega à placa atravessando a interconexão. Mais filas que CPUs só acrescentam interrupções.
## Cuidado
Mudar **reinicia a porta** (o link cai por um instante) e move as interrupções: a afinidade de CPU e IRQ vem no G1.26c."##,
    ),
    (
        "tuning.port.tx_pause",
        r##"## O que faz
Controle de fluxo 802.3x, transmissão: a porta envia quadros de pausa quando o anel de recepção enche.
## Quando mudar
Desligado num roteador (o padrão do ice da Intel): uma pausa para a porta inteira, então um receptor lento atrasa todos os fluxos (bloqueio de cabeça de fila). Descartar sai mais barato que parar; o TCP lida com o descarte.
## Cuidado
Alguns switches e redes de storage dependem da pausa; combine com o outro lado. Mudar pode renegociar o link."##,
    ),
    (
        "tuning.port.tx_ring",
        r##"## O que faz
Descritores no anel de TX da porta: pacotes que a placa enfileira para o cabo (transmissão) antes de ter de descartar ("missed").
## Quando aumentar
Quando os descartes de transmissão crescem ou a porta envia rajadas a 10 Gb/s ou mais. Os guias da Intel e da Mellanox sobem até o máximo para encaminhamento.
## Cuidado
Mudar **reinicia a porta**: o link cai por um instante (use Safe Mode). Um anel maior usa mais memória e deixa uma fila guardar mais atraso numa sobrecarga."##,
    ),
    (
        "tuning.port.tx_usecs",
        r##"## O que faz
Microssegundos que a placa espera depois de um pacote de transmissão antes de interromper a CPU (com a coalescência adaptativa desligada). Intel: 80 µs ≈ 12 500 interrupções por segundo por fila.
## Quando mudar
0 para a menor latência; 50–100 para poupar CPU com muitos pacotes por segundo. Com a adaptativa ligada, o driver decide.
## Cuidado
Alguns drivers arredondam (para múltiplos de 2 ou 4 µs); o CoreRouter confere o que o driver guardou."##,
    ),
    (
        "tuning.port.txqueuelen",
        r##"## O que faz
Pacotes que o kernel enfileira para a porta quando a placa está ocupada (na qdisc, antes do anel de TX). Padrão 1000.
## Quando mudar
Raramente: com fq_codel a qdisc mantém a fila curta de qualquer jeito. Uma interface virtual (VLAN, túnel) com 0 não tem fila nenhuma.
## Cuidado
Uma fila grande sem qdisc com AQM é bufferbloat: segundos de atraso sob carga."##,
    ),
    (
        "tuning.port.xps",
        r##"## O que faz
Transmit Packet Steering: cada CPU envia pela própria fila de transmissão (`xps_cpus`), a mesma CPU da IRQ daquela fila.
## Quando mudar
Ligado em portas de várias filas: sem trava dividida entre CPUs na transmissão, e as conclusões ficam na CPU que enviou.
## Cuidado
Alguns drivers configuram o XPS sozinhos; desligar devolve o mapa deles."##,
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
        "Apply to all ports with Safe Mode",
        r##"Aplicar em todas as portas com Safe Mode"##,
    ),
    (
        "Apply with Safe Mode",
        r##"Aplicar com Safe Mode"##,
    ),
    (
        "Balanced",
        r##"Balanceado"##,
    ),
    (
        "CPU and IRQ",
        r##"CPU e IRQ"##,
    ),
    (
        "CPU isolation",
        r##"Isolamento de CPUs"##,
    ),
    (
        "Changing rings or queues resets the port: its link drops for a moment. Use Safe Mode on a port you manage the router through.",
        r##"Mudar anéis ou filas reinicia a porta: o link cai por um instante. Use Safe Mode numa porta pela qual você gerencia o roteador."##,
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
        "Filtering",
        r##"Filtragem"##,
    ),
    (
        "Find",
        r##"Buscar"##,
    ),
    (
        "Flow control",
        r##"Controle de fluxo"##,
    ),
    (
        "Frequency",
        r##"Frequência"##,
    ),
    (
        "High throughput",
        r##"Alto desempenho"##,
    ),
    (
        "I understand the security risk",
        r##"Entendo o risco de segurança"##,
    ),
    (
        "Idle states",
        r##"Estados de repouso"##,
    ),
    (
        "Interrupt coalescing",
        r##"Coalescência de interrupções"##,
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
        "Next boot",
        r##"Próximo boot"##,
    ),
    (
        "Not in this kernel or network namespace (conntrack: not loaded yet).",
        r##"Não existe neste kernel ou namespace de rede (conntrack: ainda não carregado)."##,
    ),
    (
        "Not set for the next boot",
        r##"Não definido para o próximo boot"##,
    ),
    (
        "Not set: the kernel's own value is in use",
        r##"Não definido: vale o valor do próprio kernel"##,
    ),
    (
        "Not set: the machine's own value is in use",
        r##"Não definido: vale o valor da própria máquina"##,
    ),
    (
        "Not set: the port's own value is in use",
        r##"Não definido: vale o valor da própria porta"##,
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
        "Power saving",
        r##"Economia de energia"##,
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
        "Queue IRQs",
        r##"IRQs das filas"##,
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
        "Rings and queues",
        r##"Anéis e filas"##,
    ),
    (
        "Routing",
        r##"Roteamento"##,
    ),
    (
        "Running",
        r##"Em uso"##,
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
        "Security",
        r##"Segurança"##,
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
        "The driver does not let it change.",
        r##"O driver não deixa mudar."##,
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
        "This router has no CPU tuning yet: update corerouter-daemon.",
        r##"Este roteador ainda não tem ajuste de CPU: atualize o corerouter-daemon."##,
    ),
    (
        "This router has no System › Tuning yet: update corerouter-daemon.",
        r##"Este roteador ainda não tem System › Tuning: atualize o corerouter-daemon."##,
    ),
    (
        "This router has no boot parameters yet: update corerouter-daemon.",
        r##"Este roteador ainda não tem parâmetros de boot: atualize o corerouter-daemon."##,
    ),
    (
        "This router has no port tuning yet: update corerouter-daemon.",
        r##"Este roteador ainda não tem ajuste de portas: atualize o corerouter-daemon."##,
    ),
    (
        "Transmit queue",
        r##"Fila de transmissão"##,
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
        "Valid from the next boot. The A/B image does not exist yet (G1.6): the parameters are saved in the config and wait for it (G1.26h).",
        r##"Vale a partir do próximo boot. A imagem A/B ainda não existe (G1.6): os parâmetros ficam gravados na config e esperam por ela (G1.26h)."##,
    ),
    (
        "Valid from the next boot; a boot that fails goes back to the previous image.",
        r##"Vale a partir do próximo boot; um boot que falha volta para a imagem anterior."##,
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
        "fixed",
        r##"fixo"##,
    ),
    (
        "flaps link",
        r##"pisca o link"##,
    ),
    (
        "irqbalance is running: it undoes the IRQ affinity.",
        r##"O irqbalance está rodando: ele desfaz a afinidade das IRQs."##,
    ),
    (
        "needs reboot",
        r##"pede reboot"##,
    ),
    (
        "next boot",
        r##"próximo boot"##,
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
        "security risk",
        r##"risco de segurança"##,
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
        "finding.flow_control_on",
        r##"O controle de fluxo (quadros de pausa) está ligado em {nics}: uma fila cheia para a porta inteira (aba Interfaces)."##,
    ),
    (
        "finding.forwarding_off",
        r##"O encaminhamento IPv4 está desligado: este roteador não roteia."##,
    ),
    (
        "finding.irqbalance",
        r##"O irqbalance está rodando: ele move as IRQs a cada 10 s e desfaz a afinidade (pare-o: systemctl disable --now irqbalance)."##,
    ),
    (
        "finding.lro_on",
        r##"O LRO está ligado em {nics}: ele junta pacotes de um jeito que um roteador não pode encaminhar (aba Interfaces)."##,
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
        "why.boot_aspm",
        r##"Economia de energia do link PCIe desligada: uma placa acordando o link PCIe acrescenta latência aos primeiros pacotes."##,
    ),
    (
        "why.boot_cstate",
        r##"C-state máximo 1 desde o boot: sem atraso de despertar para os pacotes (mais consumo; o limite de C-state da aba CPU faz o mesmo sem reboot)."##,
    ),
    (
        "why.boot_iommu_pt",
        r##"Passthrough: o DMA do próprio host pula a tradução do IOMMU (menos custo por pacote); VFIO e SR-IOV continuam com ela."##,
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
        "why.c_states",
        r##"1 µs: as CPUs ficam no máximo em C1 e acordam na hora para um pacote (C-states profundos levam dezenas de µs)."##,
    ),
    (
        "why.coalesce_adaptive",
        r##"Coalescência adaptativa: poucas interrupções sob carga, rápidas com a placa ociosa."##,
    ),
    (
        "why.coalesce_off",
        r##"Uma interrupção por pacote: a menor latência, ao custo de CPU."##,
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
        "why.governor",
        r##"performance: as CPUs ficam no clock máximo; subir o clock numa rajada custa latência e descartes."##,
    ),
    (
        "why.gro",
        r##"O GRO junta os pacotes de um fluxo na recepção e o kernel os separa de novo no envio: menos custo por pacote, seguro para encaminhar."##,
    ),
    (
        "why.hash_l4",
        r##"Espalha os fluxos pelas rotas de mesmo custo também pela porta, não só pelo endereço."##,
    ),
    (
        "why.irq_local",
        r##"Uma IRQ de fila por CPU do nó NUMA da porta ({cpus} CPUs), fixa: sem tráfego de memória entre nós."##,
    ),
    (
        "why.keep",
        r##"O perfil {profile} mantém o valor do kernel."##,
    ),
    (
        "why.lro",
        r##"O LRO reescreve cabeçalhos sem volta: um roteador não pode encaminhar o que ele montou (o kernel o desliga junto com o forwarding)."##,
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
        "why.pause",
        r##"Quadros de pausa param a porta inteira quando uma fila enche: bloqueio de cabeça de fila para todos os fluxos."##,
    ),
    (
        "why.qdisc_fq_codel",
        r##"Uma fila de transmissão: o fq_codel mantém baixo o atraso de fila (sem bufferbloat)."##,
    ),
    (
        "why.qdisc_mq",
        r##"Várias filas de transmissão: o mq mantém uma qdisc por fila (a padrão, fq_codel), sem uma trava dividida por todas as CPUs."##,
    ),
    (
        "why.qdisc_noqueue",
        r##"Uma porta virtual envia na hora, sem fila própria: uma qdisc ali só acrescenta trabalho."##,
    ),
    (
        "why.queues",
        r##"Uma fila por CPU do nó NUMA da porta ({cpus}), até as {max} da placa."##,
    ),
    (
        "why.ring",
        r##"{value} descritores ({profile}), das {max} da placa: espaço para uma rajada sem quadros perdidos."##,
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
        "why.rps_off",
        r##"Várias filas: o RSS já espalha os fluxos; o RPS só acrescentaria trabalho."##,
    ),
    (
        "why.rps_on",
        r##"Uma fila de recepção: o RPS espalha os fluxos pelas CPUs do nó, em software."##,
    ),
    (
        "why.sockbuf",
        r##"Deixa o BGP e a API pedirem buffers de socket de 16 MiB (tabelas completas)."##,
    ),
    (
        "why.v6_routes",
        r##"O Linux {kernel} ainda limita as rotas IPv6 ao max_size: espaço para a tabela completa."##,
    ),
    (
        "why.watchdog",
        r##"O hardware reinicia o roteador se o daemon parar de responder."##,
    ),
    (
        "why.xps_off",
        r##"Uma fila de transmissão: nada a escolher."##,
    ),
    (
        "why.xps_on",
        r##"Cada CPU envia pela própria fila: sem trava dividida entre CPUs."##,
    ),
];
