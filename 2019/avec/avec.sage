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
