id: processo

Teste `failure_rolls_back_every_done_step` (netns) sem falso negativo: a comparação dos
endereços ignora o estado `tentative` do DAD do IPv6, transitório logo depois de o link subir
(reprovou o CI do PR da bateria).
