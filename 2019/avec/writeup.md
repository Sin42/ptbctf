# Avec? - Cryptanalysis challenge

Original task description:
```
Avec?
856
Author: Sin__

It's 2019 and people still use AES-CBC?

Let's encrypt stuff like it's 3019!!!
```

The concept of the challenge was to have a Python script, as small and simple as
possible, which encrypts a file of arbitrary size. The decryption process must
not be trivial and people should, hopefully, learn something new.

The script is as follows:
```python
#!/usr/bin/sage
import os
from Crypto.Cipher import AES # Use `sage -sh` to install pycryptodome for AES.MODE.GCM
from Crypto.Util.number import bytes_to_long, long_to_bytes
def do_raise_entropy(input_msg):
	cipher = AES.new("assume_nothing!!", AES.MODE_CBC, "\x00"*16)
	return cipher.encrypt(input_msg)
def polish_key(key):
	key = bytes_to_long(key[::-1])
	key = GF(2**64).fetch_int(key)
	key = key ** 0xbcafffff435
	key = long_to_bytes( key.integer_representation() )[::-1]
	assert len(key) == 8
	return key
def do_encrypt(data):
	half = polish_key( os.urandom(8) )
	key = half + half
	half2 = polish_key( os.urandom(8) )
	nonce = half2 + half2
	cipher = AES.new(key, AES.MODE_GCM, nonce = nonce[:12])
	cipher.update("PTB")
	ciphertext, tag = cipher.encrypt_and_digest( do_raise_entropy(data) )
	open("flag.bin", "wb+").write(ciphertext + tag)

do_encrypt( open("flag.txt").read() )
```

The encryption is as follows:
- a random 8 byte key is **polished**, doubled and used as AES-GCM key
- a random 8 byte key is **polished**, doubled, truncated to 12 bytes and used as AES-GCM nonce
- this cipher is used to encrypt the contents of `flag.txt`. However, another layer is added before the AES-GCM encryption: the plaintext is first encrypted with AES-CBC to `raise entropy`.

Alright, from the outset, if nothing is broken, we would have a search space of 64 bits (key) + 64 bits (nonce). Obviously, there is a problem somewhere in this construction.

The first part of this challenge lies in figuring out what the `polish_key` function does, the important part being:
```python
key = GF(2**64).fetch_int(key)
key = key ** 0xbcafffff435
```
The suspicious number `0xbcafffff435` is actually `0xffffffff * 3019`, alluding to the task text. But what exactly is happening? To illustrate, we use a smaller scale example:
```python
n = 16
k = 4
t = 3019 # any number s.t. gcd(t,2^n-1) = 1 works

N = 2 ^ n - 1
assert gcd(t, N) == 1

K = 2 ^ k - 1
# K | N
G.<a> = GF(2^n)


print "Passing all elements in G through the polish_key function to obtain set S"
g = G.multiplicative_generator()
S = set()
for x in G:
        S.add(x ^(t * K))
print "S length", len(S)

```
In this example, instead of `GF(2**64)` we use `GF(2**16)` and instead of the polish_key `(2**32 - 1) * 3019` we use `(2**4 - 1) * 3019`. The output is that S does not have `2**16` elements but only 4370 which is exactly `N / K + 1`.

Now we know that in the task script the polish_key function will output only `2**32` different values. Thus, the search space has been reduced from 64 bits (key) + 64 bits (nonce) to 32 bits (key) + 32 bits (nonce). Assuming that something is else is broken further down, could we efficiently iterate through all the `2**32` possible outputs? The answer is yes:

```python
h = g ^ t
SS = set()

print "Efficiently iterating to obtain SS"
for i in xrange(N/K):
        SS.add(h ^(i * K))
SS.add(0)
print "SS length", len(SS)
assert SS.issubset(S)
```

In the second part of this challenge, we need some more information to reduce the search space even further. Where could the problem lie and how can we use it to our advantage? The answer is in the AES-GCM construction:
![Galois Counter Mode schematic (Wikipedia)](https://upload.wikimedia.org/wikipedia/commons/2/25/GCM-Galois_Counter_Mode_with_IV.svg)

Since the output file contains both the ciphertext and authentication tag, we can make use of the latter.
Folowing the schematic, we know:
- the authentication data
- the ciphertext blocks
- the length of A and the length of C
- the authentication tag
But we don't know H and the encryption of Counter 0. If we knew these two it would be possible to check that the authentication tag is correct. However, we already know the authentication tag is correct and thus we can use it obtain the encryption of Counter 0 **if** we know H, where H is the encryption of a null block with the AES key K, the same used to encrypt Counter 0. An opportunity arises!

If we assume the AES key K known, using the auth data, the auth tag and the GCM construction, we can obtain the encryption of the Counter 0. But knowing the key K we can also decrypt it, thus revealing if the key K is correct (as the counter has a known form: a dword starting from 0).

Putting these two together, we can now iterate over the key candidates and check if the decryption of the counter succeeds. The only problem is that `2**32` iterations is not exactly trivial and pretty slow in Python/Sage; it can be done within the timeframe of the CTF though. In the original variant for this challenge, I considered running an online service with a challenge/response mechanism whereby the solver had maximum 5 minutes to solve a random instance of this problem.

My [solution](solver/solver) is written using compiler intrinsics for carry-less multiplication and AES encryption decryption and parallelized using OpenMP such that it solves any instance of the problem within 3 minutes.

```shell
$ time ./solver
Thread 0 doing from 0 to 0x20000000
Thread 7 doing from 0xe0000000 to 0x100000000
Thread 4 doing from 0x80000000 to 0xa0000000
Thread 2 doing from 0x40000000 to 0x60000000
Thread 6 doing from 0xc0000000 to 0xe0000000
Thread 1 doing from 0x20000000 to 0x40000000
Thread 5 doing from 0xa0000000 to 0xc0000000
Thread 3 doing from 0x60000000 to 0x80000000
PTBCTF{7acf3b60b0819767ea67b4d4}^C
real	1m38.168s
user	11m29.310s
sys	0m1.154s
```



Trivia: the original idea for this challenge came to me a while ago during a research you can consult [here](https://conference.hitb.org/hitbsecconf2016ams/wp-content/uploads/2015/11/D1T1-Radu-Caragea-Peering-into-the-Depths-of-TLS-Traffic-in-Real-Time.pdf) in section 5.3.4.
