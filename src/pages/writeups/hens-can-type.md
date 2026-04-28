---
layout: ../../layouts/WriteupLayout.astro
title: "Hens can type?"
tag: "Forense"
tags:
  - Forense
  - BlueHens CTF
---
**Título:** Hens can type?  
**Categoría:** Forense  
**Competencia:** BlueHens CTF  
**Descripción:** `UD SOC team recovered a USB traffic capture from a suspicious machine on campus. Investigators believe a user typed something important… Can you reconstruct what was typed? Take a closer look you might find what was left behind.`

## Reconocimiento

Para este reto nos entregan un archivo de captura:

- `challenge1.pcapng`

Al tratarse de un `pcapng`, lo primero era identificar que tipo de trafico habia dentro. En este caso no parecia un reto de red tradicional, sino algo relacionado con USB.

Una forma rapida de confirmarlo es listar algunos campos del protocolo USB:

```bash
tshark -r challenge1.pcapng \
  -T fields \
  -e usb.device_address -e usb.endpoint_address -e usb.transfer_type -e usb.urb_type -e usb.data_len
```

Con eso ya se veia trafico `usbmon`, asi que la siguiente idea fue buscar un dispositivo que se comportara como teclado HID.

## Identificacion del dispositivo

Para no revisar paquete por paquete, convenia agrupar por dispositivo, endpoint, tipo de transferencia y longitud de datos:

```bash
tshark -r challenge1.pcapng \
  -T fields \
  -e usb.device_address -e usb.endpoint_address -e usb.transfer_type -e usb.urb_type -e usb.data_len \
| awk -F'\t' 'NF>=5{k=$1"\t"$2"\t"$3"\t"$4"\t"$5; c[k]++} END{for(k in c) print c[k]"\t"k}' \
| sort -nr
```

Fragmento relevante:

```text
84    11    0x81    0x01    'C'    8
84    11    0x81    0x01    'S'    0
```

Ese patron era el mas interesante:

1. El dispositivo era el `11`.
2. El endpoint `0x81` corresponde a trafico de entrada.
3. Los paquetes de 8 bytes encajan muy bien con reportes HID de teclado.

En un teclado USB comun, esos 8 bytes suelen representar:

- byte 0: modificadores
- byte 1: reservado
- bytes 2 a 7: keycodes presionados

## Reportes HID

Con el dispositivo candidato identificado, el siguiente paso fue ver solo sus reportes utiles:

```bash
tshark -r challenge1.pcapng \
  -Y "usb.device_address==11 && usb.endpoint_address==0x81 && usb.urb_type==67" \
  -T fields \
  -e frame.number -e frame.time_relative -e usb.capdata
```

Las primeras lineas ya mostraban el formato esperado:

```text
1713  14.585992000  0200000000000000
1715  14.845040000  0200180000000000
1717  14.928966000  0200000000000000
1719  16.198273000  0200070000000000
```

Aqui se puede leer bastante informacion:

1. `0200000000000000` indica que Shift esta presionado, pero aun no hay una tecla normal activa.
2. `0200180000000000` indica Shift + keycode `0x18`.
3. `0200000000000000` vuelve a aparecer como parte de la liberacion del caracter.

Si se consulta la tabla HID de teclado, el keycode `0x18` corresponde a `u`, y con Shift pasa a `U`.

De la misma forma:

- `020007...` corresponde a `D`
- `020006...` corresponde a `C`
- `020017...` corresponde a `T`
- `020009...` corresponde a `F`
- `02002f...` corresponde a `{`

Con esas primeras teclas ya aparecia claramente el prefijo:

```text
UDCTF{
```

## Reconstruccion del texto

Desde ese punto, el trabajo era repetir el mismo proceso: tomar cada reporte no nulo, revisar si habia Shift en el byte 0 y traducir el keycode principal.

Se puede hacer a mano, pero como el proceso es repetitivo, use un script corto solamente para automatizar la tabla HID y evitar errores de transcripcion.

El script fue este:

```python
#!/usr/bin/env python3
import subprocess

PCAP = "challenge1.pcapng"

KEYMAP = {
    **{i: (chr(ord('a') + i - 0x04), chr(ord('A') + i - 0x04)) for i in range(0x04, 0x1E)},
    0x1E: ('1', '!'), 0x1F: ('2', '@'), 0x20: ('3', '#'), 0x21: ('4', '$'), 0x22: ('5', '%'),
    0x23: ('6', '^'), 0x24: ('7', '&'), 0x25: ('8', '*'), 0x26: ('9', '('), 0x27: ('0', ')'),
    0x28: ('\n', '\n'), 0x29: ('[ESC]', '[ESC]'), 0x2A: ('[BS]', '[BS]'), 0x2B: ('\t', '\t'),
    0x2C: (' ', ' '), 0x2D: ('-', '_'), 0x2E: ('=', '+'), 0x2F: ('[', '{'), 0x30: (']', '}'),
    0x31: ('\\', '|'), 0x32: ('#', '~'), 0x33: (';', ':'), 0x34: ("'", '"'), 0x35: ('`', '~'),
    0x36: (',', '<'), 0x37: ('.', '>'), 0x38: ('/', '?')
}

cmd = [
    "tshark", "-r", PCAP,
    "-Y", "usb.device_address==11 && usb.endpoint_address==0x81 && usb.urb_type==67",
    "-T", "fields",
    "-e", "frame.number",
    "-e", "frame.time_relative",
    "-e", "usb.capdata",
]

out = subprocess.check_output(cmd, text=True)

prev_keys = set()
text = []
events = []
for line in out.strip().splitlines():
    parts = line.split('\t')
    if len(parts) != 3:
        continue
    frame, trel, cap = parts
    if len(cap) != 16:
        continue
    b = [int(cap[i:i+2], 16) for i in range(0, 16, 2)]
    mod = b[0]
    shift = bool(mod & 0x22)
    keys = {k for k in b[2:8] if k != 0}

    new_keys = [k for k in b[2:8] if k != 0 and k not in prev_keys]
    for k in new_keys:
        ch = KEYMAP[k][1 if shift else 0] if k in KEYMAP else f"[0x{k:02x}]"
        text.append(ch)
        events.append((int(frame), float(trel), mod, k, ch, cap))

    prev_keys = keys

print(''.join(text))
print()
for e in events:
    print(f"{e[0]}\t{e[1]:.6f}\t0x{e[2]:02x}\t0x{e[3]:02x}\t{e[4]}\t{e[5]}")
```

Luego se ejecuto asi:

```bash
python3 decode_usb_keyboard.py
```

Salida del script:

```text
UDCTF{k3y_StR0K3E_1S_7he_wAy}
```

El valor recuperado coincide con los eventos individuales. Por ejemplo:

```text
1715  14.845040  0x02  0x18  U  0200180000000000
1741  24.472696  0x00  0x0e  k  00000e0000000000
1755  30.381289  0x02  0x2d  _  02002d0000000000
1777  39.173628  0x00  0x27  0  0000270000000000
1863  64.530112  0x02  0x04  A  0200040000000000
1875  68.298166  0x02  0x30  }  0200300000000000
```

La idea importante no era el script en si, sino entender que cada reporte de 8 bytes contenia una pulsacion de teclado, y que la captura se podia leer como una secuencia de caracteres.

## Flag

```text
UDCTF{k3y_StR0K3E_1S_7he_wAy}
```
