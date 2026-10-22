id: processo

Teste de latência do canal de controle (`a_persistent_connection_answers_in_milliseconds`) sem
falso negativo sob carga: na bateria de 10 features, com 10 `cargo xtask ci` ao mesmo tempo, a
mediana de 40 pedidos passou dos 5 ms e reprovou um PR bom. Agora vale o pedido mais rápido dos
40, com limite de 20 ms: o atraso de Nagle (~40 ms) atinge todo pedido e continua reprovando; a
carga só atrasa alguns.
