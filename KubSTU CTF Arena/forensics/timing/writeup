**Category:** Forensics / Reversing
**Flag:** `KubSTU{aU70p5y_D3l373d_P3_4nd_r3v3r53}`

> One of the temporary exports has disappeared from the portable storage device
> in the materials preparation department. The employee claims that he managed to
> copy the results before leaving and cleared the workspace, but the transfer log
> appears to be incomplete. Flag format: KubSTU{...}

**Attachment:** `last_export.rar`

## Unpacking

The attachment is a RAR5 archive (magic `52 61 72 21 1A 07 01 00`) holding a
single disk image. It's 21 KB packed and 48 MB unpacked, so the image is mostly
empty space.

```bash
unrar l last_export.rar       # last_export.img, 50331648 bytes
unrar x last_export.rar
file last_export.img
# DOS/MBR boot sector ... OEM-ID "mkfs.fat" ... label: "LASTEXPORT ", FAT (16 bit)
```

## Listing the filesystem

There's no partition table; the filesystem starts at sector 0, so The Sleuth Kit
needs no offset:

```bash
fsstat last_export.img | head    # FAT16, label LASTEXPORT
fls -r -p last_export.img
```

```
r/r 3:      LASTEXPORT  (Volume Label Entry)
d/d 5:      Archive
r/r 517:    Archive/SUMMARY.TXT
d/d 7:      Logs
r/r 581:    Logs/TRANSFER.LOG
d/d 9:      Temp
r/r 645:    Temp/cache.bin
r/r * 648:  Temp/draft_notes.tmp
r/r * 651:  Temp/unused_ledger.tmp
r/r 652:    Temp/packed.tmp
r/r 10:     README.TXT
r/r * 12:   sync_7D3.tmp
```

`*` marks deleted entries. There are three: two in `Temp` and `sync_7D3.tmp`
in the root.

## Reading the story

The live files tell you exactly what happened. `README.TXT`:

```
The routine used by the export station has a habit of writing an executable
staging file into the root of the drive before the transfer completes.
After copying the deliverables, clean the staging files and Temp directory.

If a transfer is interrupted, consult Logs\TRANSFER.LOG before re-running it.
Do not trust filename extensions for files that came from the old Windows
station; its temporary naming convention predates the current workflow.
```

`Logs/TRANSFER.LOG`, the "incomplete" log from the description:

```
2026-08-12 09:41:07  Batch 7D3: export helper started
2026-08-12 09:41:10  Batch 7D3: temporary stage object written to root
2026-08-12 09:41:13  Batch 7D3: automatic cleanup requested
2026-08-12 09:41:15  Batch 7D3: stage object removed after copy
2026-08-12 09:41:16  Temp/cache.bin retained for diagnostic review
```

Put together: an **executable** staging object for **batch 7D3** was written
to the **root** and then deleted, and its name may not end in `.exe`. That
describes the deleted `sync_7D3.tmp` exactly.

## Recovering the deleted file

```bash
istat last_export.img 12
icat -r last_export.img 12 > sync_7D3.tmp
file sync_7D3.tmp
# PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 9 sections
```

`istat` shows a 14848-byte file in 8 consecutive sectors (284–291). That matters
on FAT: deleting a file frees its cluster chain, so `icat -r` has to assume the
clusters were contiguous. Here they were, and the file starts with a clean `MZ`
header. The 8.3 directory entry reads `_YNC_7D3.TMP` because FAT overwrites the
first byte of a deleted name with `0xE5`; `fls` rebuilds the full name from the
long-filename entry.

## The decoys

The other files in `Temp` lead nowhere:

- **`draft_notes.tmp`** (deleted): "...port check complete / old exporter should
  be retired before September".
- **`unused_ledger.tmp`** (deleted): "ref: 7D2, 7D1 / no pending exports".
- **`packed.tmp`**: a `PK\x03\x04` magic glued onto 3072 random bytes. The
  header fields are garbage and there's no central directory, so it isn't a ZIP.
- **`cache.bin`**: 8192 bytes of random data, the file the log says was
  "retained for diagnostic review".

Both binary files have an entropy of about 7.95–7.98 bits/byte. Nothing
decompresses them, they have no repeated blocks, and no repeating XOR key or
clue string decodes them. As the next section shows, the executable never opens
a file and imports no crypto APIs, so nothing in the challenge ever reads them.

## Reversing the executable

It's a small MinGW build. The imports are just CRT and loader functions plus
`fwrite`, so whatever it does, it prints to stdout. `strings` finds no flag, but
`main` at `0x402590` has two short XOR loops over data in `.rdata`:

```asm
; loop 1: 19 bytes from 0x404058
mov  al, 0x23
imul eax, ebx
inc  ebx
add  eax, 0x51
xor  al, byte ptr [ebx + 0x404057]
mov  byte ptr [ebx + edx - 1], al

; loop 2: 19 bytes from 0x404044
mov  eax, ecx
imul eax, ebx          ; ebx = 0x23
sub  eax, 0x16
xor  al, byte ptr [ecx + 0x404044]
mov  byte ptr [esp + ecx + 0x27], al
```

Each byte is XORed with a key that depends on its position: `(0x23*i + 0x51)`
for the first blob and `(0x23*i - 0x16)` for the second. The results land next
to each other on the stack. Two `rep movsd` copies and a couple of `mov`s then
reorder the 38 bytes as **[16:32] + [0:16] + [32:38]**, and `fwrite` prints
them. That shuffle is why no piece of the flag shows up in `strings`.

Instead of running an unknown binary, the routine is easy to replay:

```python
import pefile

pe = pefile.PE("sync_7D3.tmp")
r = pe.sections[2].get_data()          # .rdata at 0x404000

a = bytes(((0x23*i + 0x51) & 0xff) ^ r[0x58 + i] for i in range(19))
b = bytes(((0x23*i - 0x16) & 0xff) ^ r[0x44 + i] for i in range(19))
buf = a + b                            # 3l373d_P3_4nd_r3Kub + STU{aU70p5y_Dv3r53}
print(buf[16:32] + buf[0:16] + buf[32:38])
```

```
b'KubSTU{aU70p5y_D3l373d_P3_4nd_r3v3r53}'
```

The flag reads "autopsy deleted PE and reverse", which sums up the solve.

## Takeaways

- Read the live files first. Here the README and the log described the deleted
  file's location, type and name before I recovered it.
- In FAT images, `fls` marks deleted files with `*`, and `icat -r` recovers them
  as long as their clusters were contiguous and not overwritten.
- Don't trust extensions: `file` is what told me the `.tmp` was a PE.
- Not every high-entropy file is encrypted with a key you can find. If nothing
  in the challenge reads it, it's probably a decoy.
- When `strings` comes up empty, look for small XOR loops in `main` and replay
  them in Python.
