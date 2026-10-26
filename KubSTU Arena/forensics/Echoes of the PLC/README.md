
# KubSTU CTF — Echoes of the PLC

**Category:** Forensics
**Flag:** `KubSTU{modbus_echoes_keep_the_secret}`

> *After the nightly maintenance of the “smart building” laboratory, the controller calibration log disappeared. The network dump contains a mix of monitoring, updates, equipment management, and large‑scale backups. The analyst is sure that the log was transmitted via one of the service channels, but the usual data search yielded nothing. Flag format: KubSTU{...}*

**Attachment:** `echoes_of_the_plc.pcap`

## First look

The capture is 15 minutes of industrial network traffic: about 33,000 packets
of Modbus/TCP, MQTT, HTTP, CoAP, syslog, NTP, TFTP, DHCP, ICMP and raw UDP.

```bash
capinfos echoes_of_the_plc.pcap
tshark -r echoes_of_the_plc.pcap -qz io,phs
```

The protocol hierarchy had one detail that stood out right away:

```
mbtcp                              frames:618
  modbus                           frames:618
    _ws.malformed                  frames:9
```

Nine malformed Modbus frames in an otherwise clean capture. That was my
starting point. (The name of the challenge is also a great hint)

## Finding the odd conversation

Listing TCP conversations (`-qz conv,tcp`) shows hundreds of short, identical
Modbus polls between the `10.20.140.x` and `10.20.141.x` subnets. One session
doesn't fit:

```
10.20.7.23:49310  <->  10.20.7.7:502    23 frames   start 450.93s
```

It's on a different subnet, it happens once, and it sits right in the middle of
the capture. All nine malformed frames belong to it.

## The malformed Modbus replies

```bash
tshark -r echoes_of_the_plc.pcap -Y 'tcp.port==49310 && modbus' \
  -T fields -e ip.src -e mbtcp.trans_id -e tcp.payload
```

```
10.20.7.23  16385  400100000006 07 04 0108 0009
10.20.7.7   16385  400100000014 07 04 11 e05c47e2a5e8559155b770a88d8eb36fb8
10.20.7.23  16386  400200000006 07 04 0110 0009
10.20.7.7   16386  400200000014 07 04 11 f8a8bc59c0339a347dd021967367407f67
...
10.20.7.23  16393  400900000006 07 04 0148 0009
10.20.7.7   16393  400900000004 07 04 01 ba
```

The client asks unit 7 for **Read Input Registers** (function `0x04`): 9
registers at a time, starting at `0x0108` and moving 8 registers forward each
time. Transaction IDs run from `0x4001` to `0x4009`.

The replies are malformed on purpose. A register is 2 bytes, so 9 registers
should come back as 18 bytes, but every reply claims a **byte count of 17**
(`0x11`) and carries 17 bytes of high-entropy data. The last reply carries a
single byte. That adds up to 8 × 17 + 1 = **137 bytes**.

Joined together, they start with `e0 5c 47 e2…`: not text, not a known file
header, and not something zlib or any other decompressor accepts. So the data
is encrypted, and the key has to be somewhere else in the capture.

## The echoes

Searching for "key", "flag" and similar strings only turned up noise. The
background traffic is full of random printable "backup chunks". So I looked at
everything else the two hosts in `10.20.7.0/24` did, apart from the Modbus
session:

```bash
tshark -r echoes_of_the_plc.pcap -Y 'ip.addr==10.20.7.0/24 && !(tcp.port==49310)'
```

Two things showed up.

**1. Echo replies that nobody asked for.** Between the Modbus replies, the PLC
sends ICMP Echo Replies to the client, ID `0x0c7f` (3199), sequence numbers
1–9, with no Echo Request for any of them. Eight carry 17 bytes and the last
carries 1, the same sizes as the Modbus chunks.

You can find these by matching every reply to a request on (IPs, ID, sequence).
In this capture, exactly 9 replies have no request, and they're these:

```bash
tshark -r echoes_of_the_plc.pcap -Y icmp \
  -T fields -e icmp.type -e ip.src -e ip.dst -e icmp.ident -e icmp.seq |
python3 -c "
import sys
req, rep = set(), []
for l in sys.stdin:
    t, s, d, i, q = l.split()
    (req.add((s, d, i, q)) if t == '8' else rep.append((s, d, i, q)))
print([r for r in rep if (r[1], r[0], r[2], r[3]) not in req])"
```

Wireshark's own `icmp.resp_not_found` field didn't flag them for me, so I
matched them by hand. Also, on my machine one of the payloads didn't come out
through `data.data`, presumably because Wireshark decoded it as some other
protocol. Reading the raw ICMP payload with scapy avoids that.

**2. The instructions, sent over MQTT.** Three seconds before the Modbus
session, the same client connects to the broker at `10.20.7.19:1883`,
subscribes to `facility/maintenance/calibration-manifest`, and receives:

```json
{
  "source": "Modbus/TCP unit=7 function=0x04",
  "order":  "transaction_id ascending",
  "mask":   "ICMP Echo Reply id=3199; sequence = transaction_id - 0x4000",
  "final":  "zlib"
}
```

That's the whole recipe:

1. Take the data from the function `0x04` replies of unit 7.
2. Order the chunks by transaction ID.
3. XOR each chunk with the payload of the echo reply whose sequence number is
   `transaction_id - 0x4000`.
4. zlib-decompress the result.

## Decoding

```python
import sys, zlib
from scapy.all import rdpcap, IP, TCP, ICMP, Raw

PLC, CLIENT = "10.20.7.7", "10.20.7.23"
chunks, masks = {}, {}

for p in rdpcap(sys.argv[1]):
    if IP not in p or p[IP].src != PLC or p[IP].dst != CLIENT:
        continue
    # Modbus replies: MBAP header (7) + function (1) + byte count (1) + data
    if TCP in p and p[TCP].sport == 502 and Raw in p:
        b = bytes(p[Raw])
        chunks[int.from_bytes(b[0:2], "big")] = b[9:9 + b[8]]
    # Unsolicited echo replies carry the XOR masks
    elif ICMP in p and p[ICMP].type == 0 and p[ICMP].id == 3199:
        masks[p[ICMP].seq] = bytes(p[ICMP].payload)

blob = b"".join(bytes(c ^ m for c, m in zip(chunks[t], masks[t - 0x4000]))
                for t in sorted(chunks))
print(zlib.decompress(blob).decode())
```

After the XOR, the data starts with `78 DA`, a zlib header. It decompresses
to:

```
PLC calibration journal
device=west-wing-controller-07
maintenance-window=2026-08-15T10:37:00Z
Flag: KubSTU{modbus_echoes_keep_the_secret}
```

## Why both halves matter

At first I thought the malformed Modbus frames were the whole answer. They
aren't: on their own they're ciphertext. The challenge splits the secret across
three channels that each look harmless:

| Piece | Hidden in | Cover story |
|---|---|---|
| Ciphertext | Malformed Modbus register replies | A buggy PLC |
| Key | ICMP echo replies with no request | Ping noise |
| Recipe | MQTT "calibration-manifest" message | Routine maintenance |

The "echoes" in the title are the ICMP echo replies.

## Takeaways

- Start with the protocol hierarchy. `_ws.malformed` counts are cheap leads.
- Look for conversations that don't fit: a different subnet, a single
  occurrence, or a burst in the middle of the capture.
- When you find ciphertext, list *everything* the hosts involved did, not just
  the protocol you started from.
- Pair requests with responses. Replies with no request (ICMP, DNS, ARP,
  Modbus transaction IDs) are a classic covert channel.
- Don't trust dissector-dependent fields like `data.data` for extraction. Read
  raw payloads with scapy.
