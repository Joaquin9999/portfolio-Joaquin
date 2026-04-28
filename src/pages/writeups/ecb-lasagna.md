---
layout: ../../layouts/WriteupLayout.astro
title: "Ecb-lasagna"
tag: "Criptografía"
tags:
  - Criptografía
  - AES-ECB
  - XOR
  - Bo1lers CTF
---
**Título:** Ecb-lasagna  
**Categoría:** Criptografía  
**Competencia:** Bo1lers CTF  
**Descripción:** `I think I dropped something into the lasagna, can you untangle it for me?`

## Reconocimiento

Al descomprimir el reto se obtienen tres archivos:

- `chall.py`
- `output.txt`
- `flag.txt` (señuelo local)

Código relevante de `chall.py`:

```python
import base64

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

flag = open("../flag.txt").read().strip()

s = ""
for c in flag:
    s += c * 2
flag = s

cipher = AES.new(b"lasagna!" * 2, AES.MODE_ECB)
result = b"\0" * len(flag)

for i in range(len(result)):
    ciphertext = cipher.encrypt(flag[i].encode() * 16)
    layer = b"\0" * i + ciphertext
    if len(layer) < len(result):
        layer += b"\0" * (len(result) - len(layer))
    if len(layer) > len(result):
        layer = layer[len(result):] + layer[len(layer)-len(result):len(result)]
    result = strxor(result, layer)

print(base64.b64encode(result).decode())
```

### El análisis

1. Lee la flag.
2. Duplica cada caracter (`c -> cc`).
3. Para cada posicion `i` del string duplicado:
   - 3.1 Toma el byte `x[i]`.
   - 3.2 Cifra el bloque `[x[i]] * 16` con AES-ECB y una clave fija `b"lasagna!" * 2`.
   - 3.3 Inserta ese bloque como una capa desplazada `i` posiciones.
   - 3.4 Hace XOR acumulado con el resultado real.
4. Por ultimo da la salida en base64.

La parte curiosa del reto es que no es un AES de un mensaje normal. Aqui se usa como una funcion de consulta:

- Entrada: un solo byte `b` repetido 16 veces.
- Salida: 16 bytes deterministas `E(b)`.

Entonces todo el reto se reduce a una mezcla lineal (XOR) de valores `E(b)` desplazados.

Segun el analisis, lo que debemos hacer para este reto es una transformacion combinatoria hecha encima de AES.

### Analisis de output.txt

```text
3XpvaycmXO/ycXW4lFfEzkeOcA6d+JDBBBODX9AFUc6L4IX7X4kHIj51/jYDjCnYfvKDBDueCg/2PrTMQZPw2HAlcUIDXioO2HTpxAShWQH3jz3aL7dOfoqv9cLChR/+HwIjyG0lqx78kwtVv4WgCN0+V0eeg1xnA8fxC/u0Gu83Cw5AeApiuVMch4r53IM+Q4+LUyUqs1LVFCemPBXeensXZHtzYREO7gvjyvdS/NvaMLfqjNYpOeKB4bB7WKrNhsKqIS2STUjxF8w42oNWbFAZ7CBlTalYaaw6blIefyqVVNwmw2kqEE8sUjgSATEyfuZAlKghZ/kBwseH5DLRIEYbfVa/TxehxMeHPas7/3l3dhq3C6/OjUvfz0bUQoj7Kh5/KpVUpXKSLFhTi7zMk02+Rmig/0RrxAys3eQNjD3sFc2quWLkUfQpPWLZCwOFC8oPJwcobjA23LxwTxO1Cv6QIAtNFnO7
```

Entonces, como podemos ver en `output.txt`, base64 decodifica a 360 bytes.

Como se pudo ver en `chall.py`, se define `len(result) = len(flag_duplicado)`, entonces:

- Longitud flag duplicado = 360
- Longitud flag original = 180

Entonces ya sabemos que el objetivo es recuperar 180 caracteres.

---

## Modelo matemático correcto

Definimos:

- `m = 180`
- `y_t` = byte `t` de la flag original, con `t in {0, ..., m-1}`
- `x_i` = secuencia duplicada, con `x_{2t} = x_{2t+1} = y_t`
- `E(b) = AES_k([b]^{16})` con `k = b"lasagna!lasagna!"`

La salida cruda del reto es un vector `R` de longitud `2m` tal que:

`R_j = XOR_{d=0}^{15} E(x_{j-d mod 2m})[d]`

Agrupamos por pares:

- `R_even[t] = R_{2t}`
- `R_odd[t]  = R_{2t+1}`

Ahora definimos, para `e in {0,...,7}`:

`h_e(b) = E(b)[2e] XOR E(b)[2e+1]`

Entonces:

`R_odd[t] = XOR_{e=0}^{7} h_e(y_{t-e mod m})`

Esta es la ecuación clave: una recurrencia cíclica de orden 8 sobre la secuencia `y`.

---

## Derivación breve de la separación par/impar

Para `R_{2t+1}`:

- En la suma original aparecen términos `E(x_{2t+1-d})[d]` para `d=0..15`.
- Separamos `d` en pares e impares: `d=2e` y `d=2e+1`.
- Los índices de `x` que caen son:
  - `x_{2t+1-2e}`
  - `x_{2t+1-(2e+1)} = x_{2t-2e}`
- Por la duplicación (`x_{2u} = x_{2u+1} = y_u`), ambos representan el mismo `y_{t-e}`.

Por eso los dos términos se combinan exactamente como:

`E(y_{t-e})[2e] XOR E(y_{t-e})[2e+1] = h_e(y_{t-e})`

y al acumular `e=0..7` obtenemos la fórmula anterior de `R_odd[t]`.

---

## Por qué el brute force de `y5, y6` es suficiente

Se fija el prefijo típico del reto:

`y0..y4 = bctf{`

La ecuación de `R_odd[t]` involucra `y_t, y_{t-1}, ..., y_{t-7}`. Es decir, para avanzar necesitamos una ventana de 8 variables.

- Conocemos `y0..y4` por formato.
- Quedan libres inicialmente `y5` y `y6`.
- En `t=7`, la ecuación ya depende de `y7` y de `y0..y6` (estos últimos conocidos al fijar `y5,y6`), así que `y7` queda determinado por consistencia de la ecuación.
- Luego en `t=8`, ya depende de `y8` y de valores anteriores conocidos, y así sucesivamente.

Formalmente: al fijar `y5,y6`, el sistema queda propagable hacia delante por recurrencia (con poda por alfabeto imprimible y chequeo de consistencia). Por eso basta explorar `95*95=9025` semillas en ASCII imprimible para cubrir todo el espacio relevante.

---

## Solver

```python
import base64
import os
from pathlib import Path
from Crypto.Cipher import AES

raw = base64.b64decode(Path("output.txt").read_text().strip())
m = len(raw) // 2
rodd = [raw[2 * i + 1] for i in range(m)]
reven = [raw[2 * i] for i in range(m)]

allowed = [ord(c) for c in os.environ.get("CHARSET", "".join(chr(i) for i in range(32, 127)))]
prefix = os.environ.get("PREFIX", "bctf{").encode()

cipher = AES.new(b"lasagna!" * 2, AES.MODE_ECB)
T = [list(cipher.encrypt(bytes([b]) * 16)) for b in range(256)]
h = [[T[b][2 * e] ^ T[b][2 * e + 1] for b in range(256)] for e in range(8)]

# Inversión parcial de h0 sobre el charset permitido
pre = {v: [] for v in range(256)}
for c in allowed:
    pre[h[0][c]].append(c)

def check_odd(y):
    for t in range(m):
        acc = 0
        for e in range(8):
            acc ^= h[e][y[(t - e) % m]]
        if acc != rodd[t]:
            return False
    return True

def check_even(y):
    for t in range(m):
        acc = 0
        for d in range(16):
            acc ^= T[y[((2 * t - d) % (2 * m)) // 2]][d]
        if acc != reven[t]:
            return False
    return True

sols, branches, tested = [], 0, 0

for c5 in allowed:
    for c6 in allowed:
        tested += 1
        y = [None] * m

        for i, ch in enumerate(prefix):
            y[i] = ch
        y[5], y[6] = c5, c6

        stack = [(7, y)]
        while stack:
            t, cur = stack.pop()

            if t == m:
                if cur[-1] == ord("}") and check_odd(cur) and check_even(cur):
                    sols.append(bytes(cur).decode("ascii", "replace"))
                continue

            v = rodd[t]
            for e in range(1, 8):
                v ^= h[e][cur[t - e]]

            cands = pre.get(v, [])
            if len(cands) == 1:
                cur[t] = cands[0]
                stack.append((t + 1, cur))
            else:
                branches += max(0, len(cands) - 1)
                for cand in cands:
                    nxt = cur.copy()
                    nxt[t] = cand
                    stack.append((t + 1, nxt))

print("tested:", tested)
print("branches:", branches)
print("solutions:", len(sols))
for s in sols[:5]:
    print(s)
```

Salida obtenida:

```text
tested: 9025
branches: 723
solutions: 1
bctf{y0u'v3_h349d_0f_5p4gh3tt1_c0d3,_8ut_d1d_y0u_kn0w_l454gn4_c0d3_4150_3x15t5?_1t_m34n5_y0u_c4n't_m4k3_4_ch4ng3_50m3wh3r3_w1th0ut_m4k1n6_4_ch4ng3_1n_m4n7_0th3r_p4rt5_0f_th3_c0d5.}
```

---

## Verificación final (reproducir exactamente `output.txt`)

Con la flag recuperada, se vuelve a ejecutar el mismo proceso de `chall.py` y se compara contra `output.txt`.

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

flag = "bctf{y0u'v3_h349d_0f_5p4gh3tt1_c0d3,_8ut_d1d_y0u_kn0w_l454gn4_c0d3_4150_3x15t5?_1t_m34n5_y0u_c4n't_m4k3_4_ch4ng3_50m3wh3r3_w1th0ut_m4k1n6_4_ch4ng3_1n_m4n7_0th3r_p4rt5_0f_th3_c0d5.}"

x = "".join(c * 2 for c in flag)
cipher = AES.new(b"lasagna!" * 2, AES.MODE_ECB)
result = b"\0" * len(x)

for i in range(len(result)):
    ciphertext = cipher.encrypt(x[i].encode() * 16)
    layer = b"\0" * i + ciphertext
    if len(layer) < len(result):
        layer += b"\0" * (len(result) - len(layer))
    if len(layer) > len(result):
        layer = layer[len(result):] + layer[len(layer)-len(result):len(result)]
    result = strxor(result, layer)

gen = base64.b64encode(result).decode()
ref = open("output.txt").read().strip()
print("match:", gen == ref)
```

Resultado esperado:

```text
match: True
```

---

## Flag recuperada

```text
bctf{y0u'v3_h349d_0f_5p4gh3tt1_c0d3,_8ut_d1d_y0u_kn0w_l454gn4_c0d3_4150_3x15t5?_1t_m34n5_y0u_c4n't_m4k3_4_ch4ng3_50m3wh3r3_w1th0ut_m4k1n6_4_ch4ng3_1n_m4n7_0th3r_p4rt5_0f_th3_c0d5.}
```

## Aprendizaje

Aunque era un reto de criptografía y no es mi área principal, me sorprendió lo entretenido y formativo que fue. Esta fue de las primeras veces que me animé a resolver uno de este tipo, y me dejó una muy buena experiencia: más que “romper AES”, aprendí a leer la lógica del código, encontrar estructura matemática útil y validar cada hipótesis con evidencia. Me ayudó a ganar confianza para seguir explorando retos de cripto.
