---
layout: ../../layouts/WriteupLayout.astro
title: "Freakquency"
tag: "Forense"
tags:
  - Forense
  - BlueHens CTF
---
**Título:** Freakquency  
**Categoría:** Forense  
**Competencia:** BlueHens CTF  
**Descripción:** `No se conservó el enunciado original en los archivos entregados.`

## Reconocimiento

Para este reto nos entregan un solo archivo:

- `hidden_message.wav`

Lo primero era confirmar que realmente se trataba de un audio normal y no de un contenedor con otro archivo incrustado.

```bash
file hidden_message.wav
ffprobe -v error \
  -show_entries stream=codec_name,codec_type,sample_rate,channels,duration \
  -show_entries format=duration,size \
  -of default=noprint_wrappers=1 hidden_message.wav
```

Salida relevante:

```text
hidden_message.wav: RIFF (little-endian) data, WAVE audio, IEEE Float, mono 44100 Hz
codec_name=pcm_f32le
codec_type=audio
sample_rate=44100
channels=1
duration=27.000000
size=4762858
```

Con eso ya se veia que el reto iba por la parte de audio. Antes de ir al espectrograma, convenia descartar algo mas simple como texto plano o un archivo embebido.

## Revision rapida del contenedor

Se probaron dos comprobaciones basicas:

```bash
strings -n 8 hidden_message.wav
binwalk hidden_message.wav
```

`strings` no mostraba nada util, y `binwalk` tampoco detectaba firmas de otro archivo dentro del WAV:

```text
Analyzed 1 file for 85 file signatures (187 magic patterns) in 23.0 milliseconds
```

Eso hacia mas probable que el mensaje estuviera escondido en la representacion del audio, no en el contenedor.

## Generacion del espectrograma

El siguiente paso fue convertir el audio a un espectrograma. En este tipo de retos suele ser la forma mas directa de detectar texto o patrones dibujados en frecuencias.

```bash
ffmpeg -y -i hidden_message.wav \
  -lavfi "showspectrumpic=s=4096x2048:legend=disabled:color=channel:scale=5thrt:fscale=lin:drange=160" \
  ff_channel.png
```

Con esa imagen ya se distinguia una cadena escrita en la parte baja:

![espectrograma](/writeups/assets/ff_channel.png)

Para leerla con mas claridad, convenia usar un recorte de la zona donde estaba el texto:

![recorte](/writeups/assets/spectrogram_crop_big.png)

## Lectura de la cadena

La cadena se reconocia como Base64 por dos razones:

1. Solo usa caracteres compatibles con Base64.
2. Empieza por `VURDVEZ7`, que al decodificar da `UDCTF{`.

La lectura visual mas consistente fue esta:

```text
VURDVEZ7dzB3X3kwdV9jNG5faDM0cl80X2YxbDM/fQ==
```

Habia una pequena ambiguedad en una parte intermedia de la imagen, donde un caracter podia leerse mal si uno se quedaba solo con el contraste del espectrograma. Para resolver eso, lo mejor fue validar candidatas por decodificacion y quedarse con la que producia una flag legible.

## Decodificacion

```bash
printf '%s\n' 'VURDVEZ7dzB3X3kwdV9jNG5faDM0cl80X2YxbDM/fQ==' | base64 -D
```

Salida del comando:

```text
UDCTF{w0w_y0u_c4n_h34r_4_f1l3?}
```

Eso confirmaba que la lectura correcta del espectrograma era esa y no otra parecida.

## Flag

```text
UDCTF{w0w_y0u_c4n_h34r_4_f1l3?}
```
