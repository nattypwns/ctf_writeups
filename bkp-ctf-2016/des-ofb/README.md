# Boston Key Party CTF 2016 : des ofb (Ruggles)

**Category:** Crypto
**Points:** 2
**Description:**

>Decrypt the message, find the flag, and then marvel at how broken everything is. https://s3.amazonaws.com/bostonkeyparty/2016/e0289aac2e337e21bcf0a0048e138d933b929a8c.tar

## Write-up

This challenge included a ciphertext file and some Python code indicating
that the authors used DES-OFB to encrypt a message with the flag.
Even with modern computers, brute forcing DES should take longer than
the time allotted to this CTF, so there must have been an intentional
vulnerability.

Download the challenge tar archive (cached here as
`e0289aac2e337e21bcf0a0048e138d933b929a8c.tar`) and untar for the original
python source code and ciphertext file.

```python
from Crypto.Cipher import DES

f = open('key.txt', 'r')
key_hex = f.readline()[:-1] # discard newline
f.close()
KEY = key_hex.decode("hex")
IV = '13245678'
a = DES.new(KEY, DES.MODE_OFB, IV)

f = open('plaintext', 'r')
plaintext = f.read()
f.close()

ciphertext = a.encrypt(plaintext)
f = open('ciphertext', 'w')
f.write(ciphertext)
f.close()
```

Some quick searches of the Internet revealed that DES-OFB has four extremely
weak keys.  These keys negate the feedback mechanic of the algorithm and
it into a repeating-one-time-pad.  Also, as mentioned in these articles,
with the IV and the four weak keys, anyone can quickly decrypt the
ciphertext.

>http://crypto.stackexchange.com/questions/7938/may-the-problem-with-des-using-ofb-mode-be-generalized-for-all-feistel-ciphers
>https://github.com/Alpackers/CTF-Writeups/tree/master/2016/BostonKeyParty/Crypto/des-ofb

Ignoring the obvious answers, this puzzle provides a nice opportunity to
write a generic repeating-one-time-pad solver.  The basic premise is to
combine two cipher blocks and then guess at the plain text of one block
to reveal the contents of the other.  For example message `m` is split into
two blocks and xor'd with the one-time-pad `o` resulting in the two cipher
blocks `c`.  `c1 = m1^o, c2 = m2^o`  Xor'ing the cipher blocks yields:
`c1^c2 = m1^m2`  Now we can focus at guessing common ascii characters.

Fortunately this puzzle has 97 16-byte blocks, so with a little coding
we can automate the guessing process and get a reasonable solution
generically.  The trick is to sequentially xor each cipher block with
all of the others, then xor those results with a block of spaces, and for
each set note the most frequent letters in column positions.

```python
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
```

Running this script will yield a slightly imperfect result, but it
should be clear enough to spot the solution.

```
54 6f 20 62 65 2c 65 6f 72 20 6e 6f 74 65 74 2a  To be,eor notet*
20 62 65 2c 20 74 2d 61 74 20 69 73 20 31 68 20   be, t-at is 1h
20 71 75 65 73 74 2c 6f 6e 3a 0a 57 68 20 74 2d   quest,on:.Wh t-
65 72 20 27 74 69 36 20 4e 6f 62 6c 65 37 20 2c  er 'ti6 Noble7 ,
6e 20 74 68 65 20 28 69 6e 64 20 74 6f 65 73 30  n the (ind toes0
66 66 65 72 0a 54 2d 65 20 53 6c 69 6e 22 73 65  ffer.T-e Slin"se
61 6e 64 20 41 72 37 6f 77 73 20 6f 66 65 6f 30  and Ar7ows ofeo0
74 72 61 67 65 6f 30 73 20 46 6f 72 74 30 6e 20  trageo0s Fort0n
2c 0a 4f 72 20 74 2a 20 74 61 6b 65 20 04 72 28  ,.Or t* take .r(
73 20 61 67 61 69 2b 73 74 20 61 20 53 20 61 65  s agai+st a S ae
6f 66 20 74 72 6f 30 62 6c 65 73 2c 0a 04 6e 21  of tro0bles,..n!
20 62 79 20 6f 70 35 6f 73 69 6e 67 20 20 6e 21   by op5osing  n!
20 74 68 65 6d 3a 65 74 6f 20 64 69 65 69 20 31   them:eto diei 1
6f 20 73 6c 65 65 35 0a 4e 6f 20 6d 6f 37 65 7e  o slee5.No mo7e~
20 61 6e 64 20 62 3c 20 61 20 73 6c 65 20 70 69   and b< a sle pi
20 74 6f 20 73 61 3c 20 77 65 20 65 6e 21 0a 11   to sa< we en!..
68 65 20 48 65 61 37 74 2d 61 63 68 65 69 20 24  he Hea7t-achei $
6e 64 20 74 68 65 65 74 68 6f 75 73 61 2b 64 65  nd theethousa+de
4e 61 74 75 72 61 29 20 73 68 6f 63 6b 36 0a 11  Natura) shock6..
68 61 74 20 46 6c 20 73 68 20 69 73 20 2d 65 2c  hat Fl sh is -e,
72 20 74 6f 3f 20 62 54 69 73 20 61 20 26 6f 2b  r to? bTis a &o+
73 75 6d 6d 61 74 2c 6f 6e 0a 44 65 76 2a 75 31  summat,on.Dev*u1
6c 79 20 74 6f 20 27 65 20 77 69 73 68 20 64 6b  ly to 'e wish dk
20 54 6f 20 64 69 20 2c 20 74 6f 20 73 29 65 20   To di , to s)e
70 2c 0a 54 6f 20 36 6c 65 65 70 2c 20 35 65 37  p,.To 6leep, 5e7
63 68 61 6e 63 65 65 74 6f 20 44 72 65 24 6d 7e  chanceeto Dre$m~
20 61 79 65 2c 20 31 68 65 72 65 27 73 65 74 2d   aye, 1here'set-
65 20 72 75 62 2c 4f 46 6f 72 20 69 6e 65 74 2d  e rub,OFor inet-
61 74 20 73 6c 65 20 70 20 6f 66 20 64 20 61 31  at sle p of d a1
68 2c 20 77 68 61 31 20 64 72 65 61 6d 36 20 28  h, wha1 dream6 (
61 79 20 63 6f 6d 20 2c 0a 57 68 65 6e 65 77 20  ay com ,.Whenew
20 68 61 76 65 20 36 68 75 66 66 6c 65 21 20 2a   have 6huffle! *
66 66 20 74 68 69 36 20 6d 6f 72 74 61 29 20 26  ff thi6 morta) &
6f 69 6c 2c 0a 4d 30 73 74 20 67 69 76 20 20 30  oil,.M0st giv  0
73 20 70 61 75 73 20 2e 20 54 68 65 72 20 27 36  s paus . Ther '6
20 74 68 65 20 72 20 73 70 65 63 74 0a 11 68 24   the r spect..h$
74 20 6d 61 6b 65 36 20 43 61 6c 61 6d 2c 74 3c  t make6 Calam,t<
20 6f 66 20 73 6f 65 6c 6f 6e 67 20 6c 2c 66 20   of soelong l,f
3a 0a 46 6f 72 20 32 68 6f 20 77 6f 75 29 64 65  :.For 2ho wou)de
62 65 61 72 20 74 2d 65 20 57 68 69 70 36 20 24  bear t-e Whip6 $
6e 64 20 53 63 6f 37 6e 73 20 6f 66 20 31 69 28  nd Sco7ns of 1i(
65 2c 0a 54 68 65 65 4f 70 70 72 65 73 36 6f 37  e,.TheeOppres6o7
27 73 20 77 72 6f 2b 67 2c 20 74 68 65 65 70 37  's wro+g, theep7
6f 75 64 20 6d 61 2b 27 73 20 43 6f 6e 31 75 28  oud ma+'s Con1u(
65 6c 79 2c 0a 54 2d 65 20 70 61 6e 67 36 20 2a  ely,.T-e pang6 *
66 20 64 65 73 70 2c 73 65 64 20 4c 6f 33 65 69  f desp,sed Lo3ei
20 74 68 65 20 4c 24 77 e2 80 99 73 20 21 65 29   the L$w...s !e)
61 79 2c 0a 54 68 20 20 69 6e 73 6f 6c 20 6e 26  ay,.Th  insol n&
65 20 6f 66 20 4f 23 66 69 63 65 2c 20 24 6e 21  e of O#fice, $n!
20 74 68 65 20 53 35 75 72 6e 73 0a 54 2d 61 31   the S5urns.T-a1
20 70 61 74 69 65 2b 74 20 6d 65 72 69 31 20 2a   patie+t meri1 *
66 20 74 68 65 20 30 6e 77 6f 72 74 68 3c 20 31  f the 0nworth< 1
61 6b 65 73 2c 0a 12 68 65 6e 20 68 65 65 68 2c  akes,..hen heeh,
6d 73 65 6c 66 20 28 69 67 68 74 20 68 2c 73 65  mself (ight h,se
51 75 69 65 74 75 36 20 6d 61 6b 65 0a 12 69 31  Quietu6 make..i1
68 20 61 20 62 61 37 65 20 42 6f 64 6b 2c 6e 7a  h a ba7e Bodk,nz
20 57 68 6f 20 77 2a 75 6c 64 20 46 61 37 64 20   Who w*uld Fa7d
6c 73 20 62 65 61 37 2c 0a 54 6f 20 67 37 75 2b  ls bea7,.To g7u+
74 20 61 6e 64 20 36 77 65 61 74 20 75 2b 64 20  t and 6weat u+d
72 20 61 20 77 65 24 72 79 20 6c 69 66 20 2c 4f  r a we$ry lif ,O
42 75 74 20 74 68 24 74 20 74 68 65 20 21 72 20  But th$t the !r
61 64 20 6f 66 20 36 6f 6d 65 74 68 69 2b 67 65  ad of 6omethi+ge
61 66 74 65 72 20 21 65 61 74 68 2c 0a 11 68 20  after !eath,..h
20 75 6e 64 69 73 26 6f 76 65 72 65 64 65 43 2a   undis&overedeC*
75 6e 74 72 79 2c 65 66 72 6f 6d 20 77 2d 6f 36  untry,efrom w-o6
65 20 62 6f 75 72 2b 0a 4e 6f 20 54 72 24 76 20  e bour+.No Tr$v
6c 6c 65 72 20 72 20 74 75 72 6e 73 2c 65 50 30  ller r turns,eP0
7a 7a 6c 65 73 20 31 68 65 20 77 69 6c 29 2c 4f  zzles 1he wil),O
41 6e 64 20 6d 61 2e 65 73 20 75 73 20 37 61 31  And ma.es us 7a1
68 65 72 20 62 65 24 72 20 74 68 6f 73 20 20 2c  her be$r thos  ,
6c 6c 73 20 77 65 65 68 61 76 65 2c 0a 11 68 24  lls weehave,..h$
6e 20 66 6c 79 20 31 6f 20 6f 74 68 65 37 73 65  n fly 1o othe7se
74 68 61 74 20 77 20 20 6b 6e 6f 77 20 2b 6f 31  that w  know +o1
20 6f 66 2e 0a 54 2d 75 73 20 43 6f 6e 36 63 2c   of..T-us Con6c,
65 6e 63 65 20 64 2a 65 73 20 6d 61 6b 20 20 06  ence d*es mak  .
6f 77 61 72 64 73 65 6f 66 20 75 73 20 24 6c 29  owardseof us $l)
2c 0a 41 6e 64 20 31 68 75 73 20 74 68 20 20 0b  ,.And 1hus th  .
61 74 69 76 65 20 2d 75 65 20 6f 66 20 17 65 36  ative -ue of .e6
6f 6c 75 74 69 6f 2b 0a 49 73 20 73 69 26 6b 29  olutio+.Is si&k)
69 65 64 20 6f 27 20 72 2c 20 77 69 74 2d 20 31  ied o' r, wit- 1
68 65 20 70 61 6c 20 20 63 61 73 74 20 2a 66 65  he pal  cast *fe
54 68 6f 75 67 68 31 2c 0a 41 6e 64 20 20 6e 31  Though1,.And  n1
65 72 70 72 69 73 20 73 20 6f 66 20 67 37 65 24  erpris s of g7e$
74 20 70 69 74 63 2d 20 61 6e 64 20 6d 2a 6d 20  t pitc- and m*m
6e 74 2c 0a 57 69 31 68 20 74 68 69 73 65 72 20  nt,.Wi1h thiser
67 61 72 64 20 74 2d 65 69 72 20 43 75 37 72 20  gard t-eir Cu7r
6e 74 73 20 74 75 37 6e 20 61 77 72 79 69 0a 04  nts tu7n awryi..
6e 64 20 6c 6f 73 20 20 74 68 65 20 6e 24 6d 20  nd los  the n$m
20 6f 66 20 41 63 31 69 6f 6e 2e 20 53 2a 66 31   of Ac1ion. S*f1
20 79 6f 75 20 6e 2a 77 2c 0a 54 68 65 65 66 24   you n*w,.Theef$
69 72 20 4f 70 68 20 6c 69 61 3f 20 4e 3c 6d 35  ir Oph lia? N<m5
68 2c 20 69 6e 20 31 68 79 20 4f 72 69 36 6f 2b  h, in 1hy Ori6o+
73 0a 42 65 20 61 29 6c 20 6d 79 20 73 2c 6e 36  s.Be a)l my s,n6
20 72 65 6d 65 6d 27 65 72 65 64 2e 20 07 4b 15   remem'ered. .K.
43 54 46 7b 73 6f 1a 69 74 73 5f 6a 75 36 74 1a  CTF{so.its_ju6t.
61 5f 73 68 6f 72 31 5f 72 65 70 65 61 31 69 2b  a_shor1_repea1i+
67 5f 6f 74 70 21 38 0a 31 33 32 34 35 73 37 7d  g_otp!8.13245s7}
```

To get the final answer, make the necessary corrections to the first
plain text block (To be, or not to), and xor it the first cipher block
for the one-time-pad.  Then apply this pad to the rest of the cipher
blocks.

```python
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
```

```
24 44 5b 8d f6 0b 73 bc 31 33 32 34 35 36 37 38  $D[...s.13245678
To be, or not to be, that is the question:
Whether 'tis Nobler in the mind to suffer
The Slings and Arrows of outrageous Fortune,
Or to take Arms against a Sea of troubles,
And by opposing end them: to die, to sleep
No more; and by a sleep, to say we end
The Heart-ache, and the thousand Natural shocks
That Flesh is heir to? 'Tis a consummation
Devoutly to be wished. To die, to sleep,
To sleep, perchance to Dream; aye, there's the rub,
For in that sleep of death, what dreams may come,
When we have shuffled off this mortal coil,
Must give us pause. There's the respect
That makes Calamity of so long life:
For who would bear the Whips and Scorns of time,
The Oppressor's wrong, the proud man's Contumely,
The pangs of despised Love, the Law’s delay,
The insolence of Office, and the Spurns
That patient merit of the unworthy takes,
When he himself might his Quietus make
With a bare Bodkin? Who would Fardels bear,
To grunt and sweat under a weary life,
But that the dread of something after death,
The undiscovered Country, from whose bourn
No Traveller returns, Puzzles the will,
And makes us rather bear those ills we have,
Than fly to others that we know not of.
Thus Conscience does make Cowards of us all,
And thus the Native hue of Resolution
Is sicklied o'er, with the pale cast of Thought,
And enterprises of great pitch and moment,
With this regard their Currents turn awry,
And lose the name of Action. Soft you now,
The fair Ophelia? Nymph, in thy Orisons
Be all my sins remembered. BKPCTF{so_its_just_a_short_repeating_otp!}
```
