#!/usr/bin/env python
import bcrypt
import sys
from compression import AESCipher

def encryptAlg(aes, password):
    return aes.encrypt(password)

def hashPsw(aes, password):
    encryptedStr = encryptAlg(aes, password)
    return bcrypt.hashpw(encryptedStr, bcrypt.gensalt(12))

def check_password(password, hashed):
    return bcrypt.checkpw(password, hashed)

def comp(aes, psw1, psw2):
    print( "[COMP] psw1 = %s, psw2 = %s" % (psw1, psw2));
    hash1 = hashPsw(aes, psw1)
    psw2 = encryptAlg(aes, psw2)
    if check_password(psw2, hash1):
        print( "[COMP] true");
    else:
        print( "[COMP] false");

def printPsw(aes, password):
    print( "[INPUT] %s" % password);
    print( "[OUTPUT] %s" % hashPsw(aes, password));

def main():
    aes = AESCipher()
    psw1 = 'pass123'; # b turns this string into a byte array
    psw2 = '123pass';
    printPsw(aes, psw1)
    printPsw(aes, psw2)
    comp(aes, psw1, psw1)
    comp(aes, psw1, psw2)

if __name__ == '__main__':
    main()
