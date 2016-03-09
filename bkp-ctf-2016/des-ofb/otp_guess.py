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

p_blocks = []

for b in range(len(c_blocks)):
  xors = []
  for i in range(len(c_blocks)):
    if b != i:
      xors.append(strxor(c_blocks[b], c_blocks[i]))

  freqs = [{} for i in range(16)]
  for i in range(len(xors)):
    x = strxor(b" "*16, xors[i])
    for j in range(16):
      if x[j] in freqs[j]:
        freqs[j][x[j]] += 1
      else:
        freqs[j][x[j]] = 1

  y = []
  for i in range(16):
    x = sorted(freqs[i].items(), key=lambda x: (x[1],x[0]), reverse=True)
    if len(x) > 0:
      y.append(x[0][0])
  p_blocks.append(bytes(y))

for block in p_blocks:
  hexdump(block)
