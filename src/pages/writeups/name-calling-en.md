---
layout: ../../layouts/WriteupLayout.astro
title: "Name Calling"
tag: "Forensics"
tags:
  - Forensics
  - BlueHens CTF
---
**Title:** Name Calling  
**Category:** Forensics  
**Competition:** BlueHens CTF  
**Description:** `I think someone called you chicken. You should do something about it`

## Recon

For this challenge we are given a single file:

- `yousaidwhat.pcapng`

Since it is a packet capture, the first step was to understand what happened on the network and check whether any exchange contained a clue, a useful file, or the flag itself.

The first thing to verify was that we were actually dealing with a network capture:

```bash
file yousaidwhat.pcapng
```

Relevant output:

```text
pcapng capture file - version 1.0
```

With that confirmed, the next step was traffic triage. In network forensics it is usually helpful to answer these questions first:

1. Which hosts are talking to each other
2. Which protocol looks the most relevant
3. Whether any file transfer took place

## Initial Traffic Analysis

Looking at the TCP conversations, the most interesting pattern was the communication between `172.16.248.1` and `172.16.248.147`, especially on port `8000`:

```bash
tshark -r yousaidwhat.pcapng -q -z conv,tcp
```

Useful fragment:

```text
172.16.248.1:65255 <-> 172.16.248.147:8000
172.16.248.1:64889 <-> 172.16.248.147:8000
172.16.248.1:65102 <-> 172.16.248.147:8000
```

That pointed to an HTTP server or at least to some kind of resource exchange. The next step was to list the HTTP requests instead of reviewing packets one by one:

```bash
tshark -r yousaidwhat.pcapng -Y http.request \
  -T fields \
  -e frame.number -e ip.src -e ip.dst -e tcp.dstport -e http.request.uri
```

This was the important part:

```text
32   172.16.248.1  172.16.248.147  8000  /decoy2.txt
45   172.16.248.1  172.16.248.147  8000  /decoy1.txt
152  172.16.248.1  172.16.248.147  8000  /whoareyoucalling.zip
228  172.16.248.1  172.16.248.147  8000  /whossliming.jpg
279  172.16.248.1  172.16.248.147  8000  /stinky.jpeg
325  172.16.248.1  172.16.248.147  8000  /chicken.jpg
```

At that point a clear pattern appeared. Some files were obvious decoys (`decoy1`, `decoy2`), while others were much more relevant, such as `whoareyoucalling.zip` and `chicken.jpg`.

## Extracting HTTP Objects

Instead of following everything directly in Wireshark or through streams, the most practical approach was to extract the HTTP objects and inspect them as regular files:

```bash
mkdir -p extracted/http
tshark -r yousaidwhat.pcapng --export-objects http,extracted/http
ls extracted/http
```

The exported files included:

- `whoareyoucalling.zip`
- `whossliming.jpg`
- `stinky.jpeg`
- `chicken.jpg`
- several `decoy*.txt`

The `decoy*.txt` files did not look promising, so they were checked quickly just to confirm they were noise:

```bash
head -n 20 extracted/http/decoy1.txt
head -n 20 extracted/http/decoy2.txt
```

They were just error responses, so it made sense to discard them and focus on the useful files.

## The Protected ZIP

The most suspicious file was `whoareyoucalling.zip`, since its name suggested it might directly contain the answer.

First, its contents were listed:

```bash
unzip -l extracted/http/whoareyoucalling.zip
```

Relevant output:

```text
whoareyoucalling.txt
```

That was a good sign: a small ZIP containing a single `.txt` file often means either the flag or the final clue. The problem was that it could not be read directly:

```bash
unzip -p extracted/http/whoareyoucalling.zip whoareyoucalling.txt
```

The ZIP required a password.

At this point the next hypothesis mattered. Brute force did not make much sense here, since the challenge already gave enough thematic context to suggest that the password was hidden somewhere else in the same capture.

## Finding the Password

Since several images were downloaded together with the ZIP, checking metadata was a reasonable next step. In forensic challenges it is a common place to hide clues, and it is quick to verify.

The images were inspected with `exiftool`:

```bash
exiftool extracted/http/chicken.jpg
```

That revealed the key clue:

```text
Copyright : 6e6f626f64792063616c6c73206d6520636869636b656e21
```

That did not look like plain text, but it did look like hexadecimal. The next step was to decode it:

```bash
echo 6e6f626f64792063616c6c73206d6520636869636b656e21 | xxd -r -p
```

Result:

```text
nobody calls me chicken!
```

The phrase matched both the challenge title and the description. It was clearly a strong candidate for the ZIP password.

## Visual Evidence

The image containing the suspicious metadata was this one:

![chicken](/writeups/assets/chicken.jpg)

The image alone does not reveal the password, but it reinforces the "chicken" theme that matches both the prompt and the hidden metadata string.

## Final Flag Extraction

Once the phrase had been decoded, the only thing left was to try it:

```bash
unzip -P "nobody calls me chicken!" -p extracted/http/whoareyoucalling.zip whoareyoucalling.txt
```

Command output:

```text
UDCTF{wh4ts_wr0ng_mcf1y}
```

## Flag

```text
UDCTF{wh4ts_wr0ng_mcf1y}
```
