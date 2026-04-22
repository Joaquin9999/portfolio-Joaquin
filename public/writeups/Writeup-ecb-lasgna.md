# Writeup-ecb-lasgna

Titulo: Esc-Lasagna

Categoria: Criptografia

Competencia: Bo1lers CTF - 2026

Descripcion: I think I dropped something into the lasagna, can you untangle it for me?

## Reconocimiento

### Analisis de chall.py

En este reto nos dan un zip, al descomprimirlo nos dan 3 archivos:

- chall.py
- output.txt
- flag.txt(Señuelo local)

Se hizo un analisis de chall.py, que es el archivo que contiene la logica del cifrado:

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

El analisis:

1. Lee la flag
2. Duplica cada caracter ( c→ cc)
3. Para cada posicion i del string duplicado:
3.1. Toma el byte x[i].
3.2. Cifra el bloque [x[i]]*16 con AES-ECB  y una clave fija b”lasagna!*2
3.3. inserta ese bloque como una capa desplazada i posiciones.
3.4. Hace XOR acumulado con el resultado real
4. Por ultimo da la salida en base64

La parte curiosa del reto es que no es un AES de un mensaje normal. Aqui se usa como una funcion de consulta:

- **Entrada:** Un solo byte b repetido 16 veces
- **Salida:** 16 bytes deterministas E(b)

Entonces todo el reto se reduce a una mezcla lineal (XOR) de valores E(b) desplazados.

Segun el analisis lo que debemos hacer para este reto es una transformacion combinatoria hecha encima de AES.

### Analisis de output.txt

```jsx
3XpvaycmXO/ycXW4lFfEzkeOcA6d+JDBBBODX9AFUc6L4IX7X4kHIj51/jYDjCnYfvKDBDueCg/2PrTMQZPw2HAlcUIDXioO2HTpxAShWQH3jz3aL7dOfoqv9cLChR/+HwIjyG0lqx78kwtVv4WgCN0+V0eeg1xnA8fxC/u0Gu83Cw5AeApiuVMch4r53IM+Q4+LUyUqs1LVFCemPBXeensXZHtzYREO7gvjyvdS/NvaMLfqjNYpOeKB4bB7WKrNhsKqIS2STUjxF8w42oNWbFAZ7CBlTalYaaw6blIefyqVVNwmw2kqEE8sUjgSATEyfuZAlKghZ/kBwseH5DLRIEYbfVa/TxehxMeHPas7/3l3dhq3C6/OjUvfz0bUQoj7Kh5/KpVUpXKSLFhTi7zMk02+Rmig/0RrxAys3eQNjD3sFc2quWLkUfQpPWLZCwOFC8oPJwcobjA23LxwTxO1Cv6QIAtNFnO7
```

Entonces como podemos ver en output.txt, base64 decodifica a 360 bytes.

Como se pudo ver en [chall.py](http://chall.py) se define len(result) = len(flag_duplicado), entonces:

- Longitud flag duplicado = 360
- Longitud flag original = 180

Entonces ya sabemos que el objetivo es recuperar 180 caracteres.

## Entendimiento de conceptos para solucionar el reto

Para poder empezar a solucionar el reto debemos tener varios conceptos, para poder empezar a plantear hipotesis y realizar el solver:

#### AES-ECB

Como podemos ver en el nombre esto es un cifrado AES,entonces tengamos claros las cualidades de este cifrado(AES-ECB):

- AES cifra bloques de 16 bytes
- ECB Significa que cada bloque se cifra por separado
- AES Necesita una clave para ser cifrado
- Si dos bloques de entrada son iguales, producen el mismo bloque cifrado(Se da por ECB)

Entonces para este caso, podemos ver que la clave que se uso es:

```python
cipher = AES.new(b"lasagna!" * 2, AES.MODE_ECB)
```

Que esto nos da como resultado:

```python
b"lasagna!" * 2 = b"lasagna!lasagna!"
```

Esto nos da 16 bytes, asi que se usa como clave de **AES-128.**

ECB Es un modo de cifrado que es bastante facil de reconocer y no sea seguro para muchos usos reales, porque este revela patrones.

- mismo bloque + misma clave → mismo ciphertext en ECB

#### XOR

XOR es una operacion de bits.

Compara 2 bits y devuelve

| 0 | XOR | 0 | = 0 |
| --- | --- | --- | --- |
| 1 | XOR | 0 | = 1 |
| 0 | XOR | 1 | = 1 |
| 1 | XOR | 1 | = 0 |

La idea importante es esta:

- si se hace la operacion dato XOR clave se cifra
- Si al resultado se le vuelve a hacer XOR con la misma clave, se recupera el original

Ejemplo de cifrado:

A: Dato

K: Clave

C: Cifrado

```
A = 01000001
K = 00001101
C = A XOR K = 01001100
```

Ejemplo de descifrado

```
C XOR K = A
```

#### Base64

Basicamente lo que hace base64 es convertir bytes en texto legible, como funciona base64:

- Toma los bits de los datos
- Los agrupa de 6 bits en 6 bits
- cada grupo de 6 bits se cambia por un carácter de una tabla de 64 símbolos

Entonces lo primero que se debe hacer es convertir el texto a ASCII:

```
Texto:   M        a        n
ASCII:   01001101 01100001 01101110
```

Luego se debe agrupar de 6 bits y convertir a decimal:

```
010011 010110 000101 101110
19     22     5      46
```

Ya por ultimo se busca en tabla de 64 caracteres el equivalente para cada numero y asi tenemos el texto en base64:

```
Man → TWFu
```

## Hipotesis

Luego de entender bien el chall.py, los diferente conceptos que salen en el reto, podemos empezar a plantearnos hipotesis:

#### Inversion byte-a-byte directa (FALLIDA)

Se intento analizar colisiones por posicion en AES ([b]*16) [d], con este script:

```python
#!/usr/bin/env python3

from collections import Counter, defaultdict
from Crypto.Cipher import AES

KEY = b"lasagna!" * 2

def main():
    cipher = AES.new(KEY, AES.MODE_ECB)

    table = [[0] * 16 for _ in range(256)]
    for b in range(256):
        enc = cipher.encrypt(bytes([b]) * 16)
        for i in range(16):
            table[b][i] = enc[i]

    print("Colisiones por posicion:")
    for i in range(16):
        values = [table[b][i] for b in range(256)]
        count = Counter(values)
        print(f"pos={i:2d} unique={len(count):3d} collisions={256 - len(count):3d}")

    pos = 0
    reverse_map = defaultdict(list)
    for b in range(256):
        reverse_map[table[b][pos]].append(b)

    repeated = [(out, bs) for out, bs in reverse_map.items() if len(bs) > 1]
    repeated.sort(key=lambda x: len(x[1]), reverse=True)

    print("\\nEjemplos en pos=0:")
    for out, bs in repeated[:5]:
        print(f"{out:02x} <- {bs}")

    print("\\nColisiones en XOR de pares:")
    for e in range(8):
        values = [table[b][2 * e] ^ table[b][2 * e + 1] for b in range(256)]
        count = Counter(values)
        print(f"e={e} unique={len(count):3d} collisions={256 - len(count):3d}")

if __name__ == "__main__":
    main()

```

Resultado:

```
Colisiones por posición:
pos= 0 unique=155 collisions=101
pos= 1 unique=164 collisions= 92
pos= 2 unique=165 collisions= 91
pos= 3 unique=157 collisions= 99
pos= 4 unique=169 collisions= 87
pos= 5 unique=163 collisions= 93
pos= 6 unique=163 collisions= 93
pos= 7 unique=160 collisions= 96
pos= 8 unique=154 collisions=102
pos= 9 unique=154 collisions=102
pos=10 unique=162 collisions= 94
pos=11 unique=167 collisions= 89
pos=12 unique=167 collisions= 89
pos=13 unique=162 collisions= 94
pos=14 unique=174 collisions= 82
pos=15 unique=151 collisions=105

Ejemplos en pos=0:
c7 <- [51, 94, 121, 210, 237]
8e <- [30, 140, 158, 180]
40 <- [1, 19, 227]
d3 <- [7, 168, 206]
9f <- [8, 20, 33]

Colisiones en XOR de pares:
e=0 unique=169 collisions= 87
e=1 unique=161 collisions= 95
e=2 unique=160 collisions= 96
e=3 unique=162 collisions= 94
e=4 unique=161 collisions= 95
e=5 unique=173 collisions= 83
e=6 unique=158 collisions= 98
e=7 unique=162 collisions= 94

```

Explicacion de resultados:

1. Para cada posicion i, si hubiera inversion local perfecta, esperariamos unique=256 y collisions=0.
2. Pero en todas las posiciones hay muchas colisiones, por ejemplo: pos=0 tiene 101 colisiones
3. Los ejemplos como c7 <- [51, 94, 121, 210, 237] muestran que un mismo byte de salida puede venir de 5 bytes de entrada distintos.

Por que fallo esta hipotesis
Para esta estrategia asume que se puede recuperar x[j] mirando su byte de salida, pero no corresponde realmente al diseño del reto.

Aunque una posicion aislada pareciera invertible en muchos casos, globalmente el sistema esta acoplado y subdeterminado si se ataca byte a byte y por eso se descarto esta ruta.

#### Compresion por duplicacion de flag

Luego de analizar nuevamente el chall.py, se pudo ver que el codigo antes de cifrar hace:

```
s = ""
for c in flag:
    s += c * 2
flag = s
```

Este codigo basicamente hace:

- Si la flag original es A B C
- Esa parte del codigo lo convierte en AA BB CC

Para modelarlo:

- y_t : caracter t de la flag original (t=0…179)
- x_i : caracter i del string suplicado (i=0…359)

Con esto se cumple:

- x_{2t} = y_t
- x_{2t+1} = y_t

O sea: cada caracter de y aparece dos veces seguidas en x/

Basicamente con esto, podemos reducir la solucion de 360 icognitas a 180 icognitas, permitiendonos reorganizar mejor las ecuaciones XOR y como nos dimos cuenta al analizar el script la flag deberia contener 180 caracteres, entonces coincide con nuestra hipotesis.

## Solucion del reto

La salida final no es el AES de la flag. Es una suma de XOR de muchas capas desplazadas.
Por eso, un byte de salida no corresponde a un solo byte de la flag.

La clave fue aprovechar esa duplicacion AA BB CC y trabajar con la version comprimida y de 180 caracteres.

#### Ecuacion

Entonces definimos:

- E(b) = AES_k([b]^16)
- h_e(b) = E(b)[2e] ^ E(b)[2e+1]

Para los indices impares de la salida:

$$
Rodd[t]=e=0⨁7he(yt−emod180)
$$

Los bytes impares del output.txt se vuelven una regla repetitiva de 8 terminos.
Esta regla permite recuperar caracteres en cadena si ya se tiene una base inicial/

#### Algoritmo para la solucion

1. Decodificar el output.txt de base64 y separar los bytes pares e impares
2. Precomputar E(b) para b=0…255 y luego h_e(b)
3. Fijar prefijo bctf{ para anclar los primeros caracteres de la flag
4. Probar semillas (y5, y6) en ASCII imprimible (95*95=9025 casos)
5. propagar y7..y179 usando la ecuacion impar
6. Podar ramas imposibles y validar candidatos con:
- Ecuaciones impares compeltas 
- Ecuaciones pares completas
- Cierre de formato } al final de la flag

Ya luego de definir estas cosas para el algoritmo creamos el script de solucion con ayuda de codex(GPT-5.3-Codex), para luego ajustarlo y que funcione correctamente:

```python
import base64, os
from pathlib import Path
from Crypto.Cipher import AES

raw = base64.b64decode(Path("dist/dist/output.txt").read_text().strip())
m = len(raw) // 2
rodd = [raw[2*i+1] for i in range(m)]
reven = [raw[2*i] for i in range(m)]

allowed = [ord(c) for c in os.environ.get("CHARSET", "".join(chr(i) for i in range(32, 127)))]
prefix = os.environ.get("PREFIX", "bctf{").encode()

cipher = AES.new(b"lasagna!" * 2, AES.MODE_ECB)

T = [list(cipher.encrypt(bytes([b]) * 16)) for b in range(256)]
h = [[T[b][2*e] ^ T[b][2*e+1] for b in range(256)] for e in range(8)]

pre = {v: [] for v in range(256)}
for c in allowed:
    pre[h[0][c]].append(c)

def check_odd(y):
    return all(
        rodd[t] == 0 ^ h[0][y[t % m]] ^ h[1][y[(t-1) % m]] ^ h[2][y[(t-2) % m]] ^
        h[3][y[(t-3) % m]] ^ h[4][y[(t-4) % m]] ^ h[5][y[(t-5) % m]] ^
        h[6][y[(t-6) % m]] ^ h[7][y[(t-7) % m]]
        for t in range(m)
    )

def check_even(y):
    for t in range(m):
        acc = 0
        for d in range(16):
            acc ^= T[y[((2*t-d) % (2*m)) // 2]][d]
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
                v ^= h[e][cur[t-e]]

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

if sols:
    Path("candidate_recurrence.txt").write_text("\n".join(sols))
```

Luego de ejecutar este script, podemos verificar la salida:

```
tested: 9025
branches: 723
solutions: 1
bctf{y0u'v3_h349d_0f_5p4gh3tt1_c0d3,_8ut_d1d_y0u_kn0w_l454gn4_c0d3_4150_3x15t5?_1t_m34n5_y0u_c4n't_m4k3_4_ch4ng3_50m3wh3r3_w1th0ut_m4k1n6_4_ch4ng3_1n_m4n7_0th3r_p4rt5_0f_th3_c0d5.}

```

Como podemos ver nos da una flag logica, teniendo en cuenta el formato de la flag, la longitud y que lo que esta internamente enla flag tiene sentido.

Analizando la salida se pueden ver 2 cosas clave:

- Se probaron 9025 semillas (y5, y6)
- Quedo unicamente una solucion

Ya por ultimo para verificar la flag se paso por el [chall.py](http://chall.py) para verificar que fuera igual al output.txt que se nos dio en el reto.

## Flag recuperada

```
bctf{y0u'v3_h349d_0f_5p4gh3tt1_c0d3,_8ut_d1d_y0u_kn0w_l454gn4_c0d3_4150_3x15t5?_1t_m34n5_y0u_c4n't_m4k3_4_ch4ng3_50m3wh3r3_w1th0ut_m4k1n6_4_ch4ng3_1n_m4n7_0th3r_p4rt5_0f_th3_c0d5.}
```

## Aprendizaje

Aunque era un reto de criptografía y no es mi área principal, me sorprendió lo entretenido y formativo que fue. Esta fue de las primeras veces que me animé a resolver uno de este tipo, y me dejó una muy buena experiencia: más que “romper AES”, aprendí a leer la lógica del código, encontrar estructura matemática útil y validar cada hipótesis con evidencia. Me ayudó a ganar confianza para seguir explorando retos de cripto.