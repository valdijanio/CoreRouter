id: processo

O teste `the_daemon_authenticates_through_its_radius_service` era instável e reprovou o lote do #262 e do #264 em 2026-10-26. Ele lia o log logo depois da resposta do RADIUS, mas o serviço só esvazia a fila de log do driver no tick dele, então a linha "recusado" às vezes ainda não tinha chegado. Agora o teste espera a linha aparecer, com prazo de 5 s.
