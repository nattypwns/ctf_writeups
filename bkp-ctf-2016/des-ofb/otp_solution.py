#!/usr/bin/env python3

from Crypto.Util.strxor import strxor

def hexdump(row):
  print("%s  %s" % (" ".join("%02x" % i for i in row),
        "".join([".", chr(i)][i > 31 and i < 127] for i in row)))

f = open("ciphertext", "rb")
ciphertext = f.read()
f.close()

ciphertext += b"\x00"*8
c_blocks = []
for i in range(len(ciphertext)//16):
  c_blocks.append(ciphertext[i*16:i*16+16])

pad = strxor(b"To be, or not to", c_blocks[0])
hexdump(pad)

msg = ""
for block in c_blocks:
  msg += strxor(pad, block).decode()

print(msg)
