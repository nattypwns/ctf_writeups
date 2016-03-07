# Boston Key Party CTF 2016 : ltseorg

**Category:** Crypto
**Points:** 4
**Description:**

>make some (charlie)hash collisions! ltseorg.bostonkey.party 5555
https://s3.amazonaws.com/bostonkeyparty/2016/a531382ad51f8cd2b74369e2127e11dfefb1676b.tar


## Write-up

This challenge included a network server component to which contestants
would netcat and supply two hexadecimal strings.  If the strings were
different and yet hashed to the same value, then the flag was revealed.

Download the challenge tar archive (cached here as
`a531382ad51f8cd2b74369e2127e11dfefb1676b.tar`) and untar for the source
code to the Ruby server and Python hash checker.

Running the binary gives the following output:

```bash
$ python tlseorg.py
ltseorg: missing argument
Usage: ltseorg [OPTION...] [input]
-v   Display Software version information
--check    Check if two inputs break collision resistance.

$ python tlseorg.py --check abcd beef
Failure

$ python tlseorg.py -v
ltseorg: I am not answering any questions without my lawyer present.
  ltseorg: Am I being detained?
  ltseorg: Am I free to go?
  ltseorg: Am I being detained?
  ltseorg: Am I free to go?
```

Checking out `tlseorg.py` revealed some author comments about how
this hash algorithm was "pretty much" as good as Grøstl; however, in this
case, a flaw was introduced which allowed some controllable message content
to be xor'd with each stage.  I suspect this was just a red herring,
because a much simpler flaw to exploit was in the check function.

```python
def check(hashstr1, hashstr2):
  hash1 = binascii.unhexlify(hashstr1);hash2 = binascii.unhexlify(hashstr2)
  if hashstr1 == hashstr2 or hash1 == hash2: return False
  elif hash(hash1) == hash(hash2): return True
  return False
```

The following requirements were enforced:
1. The input hexadecimal strings must differ.
2. The unhexlify'd contents of the input strings must differ.
3. The resulting hashes must match.

Fortunately for us, the Grøstl-like hash function used blocks and
therefore had to pad our input strings before hashing them.

```python
def pad_msg(msg):
  while not (len(msg) % 16 == 0): msg+="\x00"
  return msg
```

Since that happened during the to `hash()`, we could take advantage of
the padding to make two similar stings identical prior to hasing.  As
long as the input required some padding, then any trailing nulls were
enough to fool the input checks and allow us to supply nearly identical
strings.

Examples:

```bash
$ python tlseorg.py --check abcd abcd00
Success
$ python tlseorg.py --check 0000 00
Success
```

Easy 4 points:

```bash
$ nc ltseorg.bostonkey.party 5555
gimme str 1
00
gimme str 2
0000
BKPCTF{really? more crypto?}
```

