# 2026-10-26 12:00:01 by RouterOS 7.20.2
/ppp profile
add change-tcp-mss=yes local-address=100.64.255.254 name=plano-100M \
    only-one=yes rate-limit=50M/100M
set *0 dns-server=9.9.9.9
/ppp secret
add caller-id=AA:BB:CC:00:00:01 comment="Jo\C3\A3o \"apto 12\"" name=joao@isp \
    password="s3n h4\$!" profile=plano-100M remote-address=100.64.9.9 \
    service=pppoe
add disabled=yes name=maria password=M4r1a profile=plano-100M
set [ find name=maria ] comment="cancelado"
/ppp/secret add name=terse password=x; add name=two password=y
