---
layout: ../../layouts/WriteupLayout.astro
title: "Ecb-lasagna"
tag: "Cryptography"
tags:
  - Cryptography
  - AES-ECB
  - XOR
  - Bo1lers CTF
---
**Title:** Ecb-lasagna  
**Category:** Cryptography  
**Competition:** Bo1lers CTF  
**Description:** `I think I dropped something into the lasagna, can you untangle it for me?`

## Recon

After extracting the challenge files, we get:

- `chall.py`
- `output.txt`
- `flag.txt` (local decoy)

Relevant code from `chall.py`:

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

### Analysis

1. Read the flag.
2. Duplicate each character (`c -> cc`).
3. For each position `i` in the duplicated string:
   - 3.1 Take byte `x[i]`.
   - 3.2 Encrypt block `[x[i]] * 16` with AES-ECB and fixed key `b"lasagna!" * 2`.
   - 3.3 Insert that block as a layer shifted by `i` positions.
   - 3.4 XOR-accumulate with the current output.
4. Finally, encode output as Base64.

The key point is that this is not AES over a normal message stream. Here AES behaves like a deterministic query oracle:

- Input: one byte `b` repeated 16 times.
- Output: deterministic 16-byte block `E(b)`.

So the full challenge reduces to a linear XOR mixture of shifted `E(b)` values.

## Output.txt quick study

```text
3XpvaycmXO/ycXW4lFfEzkeOcA6d+JDBBBODX9AFUc6L4IX7X4kHIj51/jYDjCnYfvKDBDueCg/2PrTMQZPw2HAlcUIDXioO2HTpxAShWQH3jz3aL7dOfoqv9cLChR/+HwIjyG0lqx78kwtVv4WgCN0+V0eeg1xnA8fxC/u0Gu83Cw5AeApiuVMch4r53IM+Q4+LUyUqs1LVFCemPBXeensXZHtzYREO7gvjyvdS/NvaMLfqjNYpOeKB4bB7WKrNhsKqIS2STUjxF8w42oNWbFAZ7CBlTalYaaw6blIefyqVVNwmw2kqEE8sUjgSATEyfuZAlKghZ/kBwseH5DLRIEYbfVa/TxehxMeHPas7/3l3dhq3C6/OjUvfz0bUQoj7Kh5/KpVUpXKSLFhTi7zMk02+Rmig/0RrxAys3eQNjD3sFc2quWLkUfQpPWLZCwOFC8oPJwcobjA23LxwTxO1Cv6QIAtNFnO7
```

`output.txt` Base64-decodes to 360 bytes.

From `chall.py`, `len(result) = len(duplicated_flag)`, then:

- Duplicated flag length = 360
- Original flag length = 180

Target: recover 180 original characters.

## Correct mathematical model

Define:

- `m = 180`
- `y_t` = byte `t` of original flag, `t in {0, ..., m-1}`
- `x_i` = duplicated sequence, `x_{2t} = x_{2t+1} = y_t`
- `E(b) = AES_k([b]^{16})` with `k = b"lasagna!lasagna!"`

The raw output vector `R` (length `2m`) satisfies:

`R_j = XOR_{d=0}^{15} E(x_{j-d mod 2m})[d]`

Group by parity:

- `R_even[t] = R_{2t}`
- `R_odd[t]  = R_{2t+1}`

For `e in {0,...,7}`, define:

`h_e(b) = E(b)[2e] XOR E(b)[2e+1]`

Then:

`R_odd[t] = XOR_{e=0}^{7} h_e(y_{t-e mod m})`

This gives a cyclic order-8 recurrence over `y`.

## Short derivation for odd/even separation

For `R_{2t+1}`:

- The original sum has `E(x_{2t+1-d})[d]`, `d = 0..15`.
- Split `d` into `d=2e` and `d=2e+1`.
- Sequence indices become:
  - `x_{2t+1-2e}`
  - `x_{2t+1-(2e+1)} = x_{2t-2e}`
- Since duplication enforces `x_{2u} = x_{2u+1} = y_u`, both map to the same `y_{t-e}`.

So both terms combine as:

`E(y_{t-e})[2e] XOR E(y_{t-e})[2e+1] = h_e(y_{t-e})`

Summing `e=0..7` yields the recurrence above.

## Why brute forcing `y5, y6` is enough

We use the expected prefix:

`y0..y4 = bctf{`

Equation `R_odd[t]` depends on `y_t, y_{t-1}, ..., y_{t-7}` (window size 8).

- `y0..y4` are known.
- Unknown seeds are `y5` and `y6`.
- At `t=7`, the equation depends on `y7` plus known values `y0..y6`; therefore `y7` is constrained.
- Then `t=8` constrains `y8`, and so on.

So fixing `y5,y6` makes forward propagation possible with consistency checks and printable charset pruning. That is why `95*95 = 9025` seed pairs are sufficient in practice.

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

# Partial inversion of h0 over allowed charset
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

Output:

```text
tested: 9025
branches: 723
solutions: 1
bctf{y0u'v3_h349d_0f_5p4gh3tt1_c0d3,_8ut_d1d_y0u_kn0w_l454gn4_c0d3_4150_3x15t5?_1t_m34n5_y0u_c4n't_m4k3_4_ch4ng3_50m3wh3r3_w1th0ut_m4k1n6_4_ch4ng3_1n_m4n7_0th3r_p4rt5_0f_th3_c0d5.}
```

## Final verification (exact `output.txt` reproduction)

With the recovered flag, re-run the original transform and compare against `output.txt`:

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

Expected:

```text
match: True
```

## Recovered flag

```text
bctf{y0u'v3_h349d_0f_5p4gh3tt1_c0d3,_8ut_d1d_y0u_kn0w_l454gn4_c0d3_4150_3x15t5?_1t_m34n5_y0u_c4n't_m4k3_4_ch4ng3_50m3wh3r3_w1th0ut_m4k1n6_4_ch4ng3_1n_m4n7_0th3r_p4rt5_0f_th3_c0d5.}
```

## Learning

Even though this was a cryptography challenge and not my main area, it was surprisingly engaging and educational. This was one of my first times pushing through this type of problem end-to-end, and the main takeaway was not “breaking AES,” but learning how to read implementation logic, build useful mathematical structure, and validate each hypothesis with evidence.
