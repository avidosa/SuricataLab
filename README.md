# SuricataLab

Laboratorio de Suricata funcionando como **IPS en línea** (no como IDS pasivo): el tráfico
pasa por una cola de Netfilter, Suricata lo inspecciona y decide si lo deja pasar o lo tira.
Con reglas propias, ataques reales contra el laboratorio y las alertas analizadas después.

Mayo de 2026.

## Montaje

Tres máquinas Debian 12 en una red aislada sobre Proxmox:

| Máquina | IP | Rol |
|---|---|---|
| `lab-suricata` | 10.10.0.10 | motor IPS en línea y router del laboratorio |
| `lab-victima` | 10.10.0.20 | servidor Apache2, objetivo de los ataques |
| `lab-atacante` | 10.10.0.30 | generación de ataques: `hping3`, `ab`, `arpspoof` |

Suricata 7.0.10, instalado desde *backports* porque el paquete del repositorio principal
choca con `libhtp2`:

```bash
apt-get install -y -t bookworm-backports suricata
```

## Modo IPS: NFQUEUE

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -I FORWARD -j NFQUEUE --queue-num 0
suricata -c /etc/suricata/suricata.yaml -q 0 -v
```

Lo relevante de `suricata.yaml`:

```yaml
vars:
  address-groups:
    HOME_NET: "[10.10.0.0/24]"

nfq:
  mode: accept        # acepta por defecto; las reglas deciden el DROP
  fail-open: yes      # si Suricata cae, el tráfico pasa

checksum-validation: no   # imprescindible en virtualizado (ver más abajo)
threshold-file: /etc/suricata/threshold.conf
```

`fail-open: yes` es una decisión consciente: si el IPS se cae, se prefiere no cortar la red.
En producción habría que decidir a conciencia entre disponibilidad y seguridad; aquí interesa
que el laboratorio siga en pie.

## Reglas propias

Tres reglas, una por capa, en [`rules/lab-custom.rules`](rules/lab-custom.rules): SYN flood
(capa 4), ICMP flood (capa 3) y HTTP flood (capa 7, que necesita inspección profunda).
Todas usan `threshold:type both` con `track by_src`, para alertar una vez por ventana y por
IP origen en lugar de en cada paquete.

## Ataques y resultado

```bash
hping3 -S -p 80 --flood 10.10.0.20     # SYN flood
hping3 -1 --flood 10.10.0.20           # ICMP flood
ab -n 10000 -c 100 http://10.10.0.20/  # HTTP flood
arpspoof -i eth0 -t 10.10.0.20 10.10.0.10
```

**15 alertas** registradas, en [`results/resumen_alertas.csv`](results/resumen_alertas.csv):
8 de ICMP flood, 6 de SYN flood y 1 de HTTP flood excesivo. Más la evidencia de ARP spoofing
en la víctima. El análisis se hizo sobre `eve.json` con `jq`.

## Los tres problemas que costaron de verdad

Esta es la parte que más enseña, así que va documentada entera.

**1. El tráfico se saltaba a Suricata.** Atacante y víctima estaban en la misma `/24`, así que
se hablaban directamente por L2 vía ARP: el tráfico no pasaba nunca por el gateway donde
estaba Suricata y por tanto no entraba en la cola. El `fast.log` vacío sin ningún error.
Se arregló forzando rutas de host para que el kernel enrute a través del gateway:

```bash
# en lab-atacante
ip route add 10.10.0.20/32 via 10.10.0.10
# en lab-victima
ip route add 10.10.0.30/32 via 10.10.0.10
```

**2. Los ICMP Redirect deshacían esas rutas.** Suricata avisaba al atacante de que fuera
directo, el kernel le hacía caso y las rutas forzadas se invalidaban en segundos:

```bash
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects
```

**3. El HTTP flood no se detectaba por *checksum offloading*.** Con `checksum-validation: yes`,
en virtualizado el checksum TCP todavía no está calculado cuando el paquete entra en la cola
(lo calcula la NIC al transmitir). Suricata lo veía inválido y descartaba el paquete **en
silencio**, sin alerta y sin error. Con `checksum-validation: no` y `kill -USR2 $(pidof suricata)`
empezaron a salir las alertas de capa 7.

Los tres fallos tienen algo en común: **el log vacío no significaba que no hubiera ataque**.

## Hardening

`threshold.conf` para suprimir ruido y limitar la frecuencia de las reglas más charlatanas,
con la configuración activa verificada en caliente.

## Capturas

En [`docs/capturas/`](docs/capturas/), numeradas: arranque en modo NFQ, reglas cargadas,
NFQUEUE procesando tráfico real, alertas en tiempo real, las 15 alertas completas, el análisis
de `eve.json` con `jq`, la evidencia de ARP spoofing y el hardening.

## Autoría

Autoría: mmoreno | avidosa
