---
layout: ../../layouts/WriteupLayout.astro
title: "Freakquency"
tag: "Forensics"
tags:
  - Forensics
  - BlueHens CTF
---
**Title:** Freakquency  
**Category:** Forensics  
**Competition:** BlueHens CTF  
**Description:** `No original challenge prompt was preserved in the provided files.`

## Recon

For this challenge we are given a single file:

- `hidden_message.wav`

The first step was to confirm that it was just an audio file and not a container with another file embedded inside it.

```bash
file hidden_message.wav
ffprobe -v error \
  -show_entries stream=codec_name,codec_type,sample_rate,channels,duration \
  -show_entries format=duration,size \
  -of default=noprint_wrappers=1 hidden_message.wav
```

Relevant output:

```text
hidden_message.wav: RIFF (little-endian) data, WAVE audio, IEEE Float, mono 44100 Hz
codec_name=pcm_f32le
codec_type=audio
sample_rate=44100
channels=1
duration=27.000000
size=4762858
```

At that point it was clear the challenge was audio-based. Before moving to a spectrogram, it made sense to rule out something simpler such as plaintext or an embedded file.

## Quick Container Checks

Two basic checks were used:

```bash
strings -n 8 hidden_message.wav
binwalk hidden_message.wav
```

`strings` did not reveal anything useful, and `binwalk` did not detect any other file signatures inside the WAV:

```text
Analyzed 1 file for 85 file signatures (187 magic patterns) in 23.0 milliseconds
```

That made it much more likely that the hidden content lived in the audio representation itself rather than in the container.

## Generating the Spectrogram

The next step was to convert the audio into a spectrogram. In this kind of challenge, that is usually the most direct way to detect text or patterns drawn across frequencies.

```bash
ffmpeg -y -i hidden_message.wav \
  -lavfi "showspectrumpic=s=4096x2048:legend=disabled:color=channel:scale=5thrt:fscale=lin:drange=160" \
  ff_channel.png
```

That image already showed a string near the bottom:

![spectrogram](/writeups/assets/ff_channel.png)

To read it more clearly, it was useful to look at a crop focusing on the text area:

![crop](/writeups/assets/spectrogram_crop_big.png)

## Reading the String

The string looked like Base64 for two reasons:

1. It only used Base64-compatible characters.
2. It began with `VURDVEZ7`, which decodes to `UDCTF{`.

The most consistent reading was:

```text
VURDVEZ7dzB3X3kwdV9jNG5faDM0cl80X2YxbDM/fQ==
```

There was a small ambiguity in the middle of the image, where one character could easily be misread if we relied only on the contrast of the spectrogram. To resolve that, the best option was to test candidate strings by decoding them and keeping the one that produced a readable flag.

## Decoding

```bash
printf '%s\n' 'VURDVEZ7dzB3X3kwdV9jNG5faDM0cl80X2YxbDM/fQ==' | base64 -D
```

Command output:

```text
UDCTF{w0w_y0u_c4n_h34r_4_f1l3?}
```

That confirmed that this was the correct reading of the spectrogram.

## Flag

```text
UDCTF{w0w_y0u_c4n_h34r_4_f1l3?}
```
