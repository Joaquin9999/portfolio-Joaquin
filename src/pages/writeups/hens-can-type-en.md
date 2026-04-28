---
layout: ../../layouts/WriteupLayout.astro
title: "Hens can type?"
tag: "Forensics"
tags:
  - Forensics
  - BlueHens CTF
---
**Title:** Hens can type?  
**Category:** Forensics  
**Competition:** BlueHens CTF  
**Description:** `UD SOC team recovered a USB traffic capture from a suspicious machine on campus. Investigators believe a user typed something important… Can you reconstruct what was typed? Take a closer look you might find what was left behind.`

## Recon

For this challenge we are given a capture file:

- `challenge1.pcapng`

Since it is a `pcapng`, the first step was to identify what kind of traffic it contained. This did not look like a traditional network challenge, but rather something related to USB traffic.

A quick way to confirm that was to list a few USB protocol fields:

```bash
tshark -r challenge1.pcapng \
  -T fields \
  -e usb.device_address -e usb.endpoint_address -e usb.transfer_type -e usb.urb_type -e usb.data_len
```

That already showed `usbmon` traffic, so the next idea was to look for a device behaving like a HID keyboard.

## Identifying the Device

Instead of reading packets one by one, it was better to group them by device, endpoint, transfer type, and data length:

```bash
tshark -r challenge1.pcapng \
  -T fields \
  -e usb.device_address -e usb.endpoint_address -e usb.transfer_type -e usb.urb_type -e usb.data_len \
| awk -F'\t' 'NF>=5{k=$1"\t"$2"\t"$3"\t"$4"\t"$5; c[k]++} END{for(k in c) print c[k]"\t"k}' \
| sort -nr
```

Relevant fragment:

```text
84    11    0x81    0x01    'C'    8
84    11    0x81    0x01    'S'    0
```

This was the most interesting pattern:

1. The device was `11`.
2. Endpoint `0x81` corresponds to input traffic.
3. 8-byte packets are a very good match for keyboard HID reports.

On a common USB keyboard, those 8 bytes usually mean:

- byte 0: modifiers
- byte 1: reserved
- bytes 2 to 7: pressed keycodes

## HID Reports

Once the candidate device was identified, the next step was to look only at its useful reports:

```bash
tshark -r challenge1.pcapng \
  -Y "usb.device_address==11 && usb.endpoint_address==0x81 && usb.urb_type==67" \
  -T fields \
  -e frame.number -e frame.time_relative -e usb.capdata
```

The first lines already matched the expected format:

```text
1713  14.585992000  0200000000000000
1715  14.845040000  0200180000000000
1717  14.928966000  0200000000000000
1719  16.198273000  0200070000000000
```

There is a lot of information in those values:

1. `0200000000000000` means Shift is pressed, but no normal key is active yet.
2. `0200180000000000` means Shift + keycode `0x18`.
3. `0200000000000000` appears again as part of the key release sequence.

Using the HID keyboard table, keycode `0x18` corresponds to `u`, and with Shift it becomes `U`.

The same logic gives:

- `020007...` -> `D`
- `020006...` -> `C`
- `020017...` -> `T`
- `020009...` -> `F`
- `02002f...` -> `{`

That immediately revealed the prefix:

```text
UDCTF{
```

## Reconstructing the Text

From there, the process was just to repeat the same logic: take each non-zero report, check whether Shift was active in byte 0, and translate the main keycode.

It can be done by hand, but since the process is repetitive, I used a short script only to automate the HID lookup table and avoid transcription mistakes.

This was the script:

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

Then it was executed like this:

```bash
python3 decode_usb_keyboard.py
```

Script output:

```text
UDCTF{k3y_StR0K3E_1S_7he_wAy}
```

The recovered value matches the individual events. For example:

```text
1715  14.845040  0x02  0x18  U  0200180000000000
1741  24.472696  0x00  0x0e  k  00000e0000000000
1755  30.381289  0x02  0x2d  _  02002d0000000000
1777  39.173628  0x00  0x27  0  0000270000000000
1863  64.530112  0x02  0x04  A  0200040000000000
1875  68.298166  0x02  0x30  }  0200300000000000
```

The important part was not the script itself, but understanding that each 8-byte report represented a keyboard event, and that the capture could be read as a sequence of characters.

## Flag

```text
UDCTF{k3y_StR0K3E_1S_7he_wAy}
```
