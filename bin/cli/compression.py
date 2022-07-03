#!/usr/bin/env python

import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class MyCompression:
    tbl = [chr(i) for i in range(33,127)]

    def composeBase(self, num):
        range_len = len(self.tbl)
        answer = ''
        divisor = num % range_len
        answer += self.tbl[int(divisor)]
        remainder = num // range_len
        answer += self.tbl[int(remainder)]
        return answer

    def compress(self, password):
        arbitary_base = 36 # can be 8, 16, 24, 36
        return int(hashlib.sha1(password.encode("utf-8")).hexdigest(), arbitary_base) % (10 ** 8)

    def compress_1(self, password):
        arbitary_base = 36 # can be 8, 16, 24, 36
        arbitary_reducer = 4096
        hash_password = int(hashlib.sha1(password.encode("utf-8")).hexdigest(), arbitary_base) % (10 ** 8)
        hash_divisor = int(hash_password/arbitary_base)
        hash_remainder = int((float(hash_password/arbitary_base)-hash_divisor)*100)
        hash_reducer = hash_divisor/(arbitary_base**arbitary_reducer)
        base_divisor = self.composeBase(hash_remainder)
        base_remainder = self.composeBase(hash_reducer)
        return "%s %s" % (base_divisor, base_remainder)

class AESCipher:
    def __init__(self):
        self.bs = 16
        key = os.urandom(self.bs*2)
        iv = os.urandom(self.bs)
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    def encrypt(self, raw):
        raw = self._pad(raw)
        encryptor = self.cipher.encryptor()
        return encryptor.update(raw.encode()) + encryptor.finalize()

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
