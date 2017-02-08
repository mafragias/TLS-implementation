#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#from sys import exit
from copy import deepcopy
from math import ceil
import random, string, binascii,sys
import OpenSSL.crypto
# import partI

sys.setrecursionlimit(2500)

# Class Andvanced Encryption STandard
class AES(object):
    # Forward Rijndael Substitution Box 
    Sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
    # Inverse Rijndael Substitution Box
    Ibox = [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]              
    #Rcon: Rijndael constants
    Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d] 
    # Initialization Vector for CBC mode of operation in AES algorithm
    IV = [int(x) for x in range(0,16)]
    # Initialization of AES mode
    MODE = 'CBC'
    # Initialization of AES key size
    KEY_SIZE = 16
    
    # Galois multiplication, returns the product of a and b in a finite field.
    # gmul by @fredgj
    def mul(self,a,b):
        p = 0
        while b:
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a <<= 1
            if hi_bit:
                a ^= 0x11b
            b >>= 1
        return p
    
    # encryption based on AES Algorithm
    # Steps followed from https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    # plaintext : bytes array 
    # key : bytes array
    def encrypt(self,plaintext,key,mode):
        # fill the blanks
        
        plaintext = self.pkcs5_pad(plaintext)
        
        # check if plaintext is an array of bytes
        if type(plaintext) == bytearray and type(key)==bytearray and (len(key)==16) and (mode=="CBC"):
            t = int(ceil(float(len(plaintext))/16))     # number of iterations for the method
            chiphertext=[]  # initialization
            for i in range(0,t):
                nr = len(key)/4 + 6     # number of rounds
                
                if mode=="CBC" and i==0:
                    plaintext[i*16:i*16+16]=self.addRoundKey(plaintext[i*16:i*16+16],self.IV)
                elif mode=="CBC" and i!=0:
                    plaintext[i*16:i*16+16]=self.addRoundKey(plaintext[i*16:i*16+16],chiphertext[(i-1)*16:(i-1)*16+16])
                
                # generating round keys based on given key
                roundKeys = self.expandKey(key)
                # pre-round transformation
                chiphertext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16], roundKeys[0:16])
                # rounds
                for rnd in range(1,nr+1):
                    chiphertext[i*16:i*16+16] = self.subBytes(chiphertext[i*16:i*16+16])                
                    chiphertext[i*16:i*16+16] = self.shiftRows(chiphertext[i*16:i*16+16])
                    if rnd!=nr : #last round
                        chiphertext[i*16:i*16+16] = self.mixColumns(chiphertext[i*16:i*16+16])
                    roundKey = roundKeys[rnd*16:rnd*16+16]
                    chiphertext[i*16:i*16+16] = self.addRoundKey(chiphertext[i*16:i*16+16], roundKey)
            # returns encrypted plaintext as chiphertext
            return bytearray(chiphertext)
        else:
            print "Wrong input parameters given."   # error message
                  
    # dencryption based on AES Algorithm
    # chiphertext : bytes array
    def decrypt(self,chiphertext,key,mode):
        t = int(ceil(float(len(chiphertext))/16))  # number of iteration of the method
        # A deep copy constructs a new compound object and then, recursively, inserts copies into it of the objects found in the original
        plaintext = deepcopy(chiphertext)   # initialization as a deep copy of chiphertext
        for i in range(0,t):
            nr = len(key)/4 + 6    # number of rounds
            
            # generating round keys based on given key
            roundKeys = self.expandKey(key)
            
            # decryption rounds: encryption steps in reverse order
            for rnd in range(nr,0,-1):
                roundKey = roundKeys[rnd*16:rnd*16+16]
                plaintext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16], roundKey)
                if rnd!=nr :    # last round
                    plaintext[i*16:i*16+16] = self.dec_mixColumns(plaintext[i*16:i*16+16])
                plaintext[i*16:i*16+16] = self.dec_shiftRows(plaintext[i*16:i*16+16])
                plaintext[i*16:i*16+16] = self.dec_subBytes(plaintext[i*16:i*16+16])
                
            # post-round Transformation
            plaintext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16],roundKeys[0:16])
            
            if mode=="CBC" and i!=0:
                plaintext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16],chiphertext[(i-1)*16:(i-1)*16+16])
            if mode=="CBC" and i==0:
                 plaintext[i*16:i*16+16] = self.addRoundKey(plaintext[i*16:i*16+16],self.IV)

                 
        plaintext = self.pkcs5_unpad(str(plaintext))
        # returns dencrypted chiphertext as plaintext
        return bytearray(plaintext)
            
    # size in bytes
    def generateRandomKey(self,size):
        # The random Key consists of letters, numbers and punctuation
        if size == 16 :  # fixed key size 16 bytes
            return bytearray(''.join(random.SystemRandom().choice(string.ascii_letters+string.digits+string.punctuation) for _ in range(16)))
        else:
            print "Wrong input size. Size is given in bytes."
            
    # generate encrypted password key for AES-128 with SHA-256 
    def genEncryptedPasswordKey(self,password):
        #generating password key
        password = bytearray(password)
        ##does not need to append '\0', because sha256 outputs fixed length of 256bits##
        # ecrypt password in a fixed 256bit=32byte length using SHA256
        password = binascii.unhexlify(SHA2().sha2(password,256))
        return password[0:16]
        
    # saving selected key to a file
    def saveKeytoFile(self,key, filename):
        key = binascii.hexlify(key)     # converting key of type 'str' into type 'hex'
        keyfile = open(filename,'w+')
        keyfile.write(key)
        keyfile.close()
    
    # retrieving Key from a chosen file
    def getKeyfromFile(self,filename):
        try:
            keyfile = open(filename,'r+')
            key = keyfile.readlines()
            keyfile.close()
            # converting key of type 'hex' back into type 'str' and return it as bytearray
            return bytearray(binascii.unhexlify(key[0])) 
        except IOError:
            # error message if the file doesn't exists
            print "Not valid input file "
    
    # a non-linear substitution step where each byte is replaced with another according to Sbox lookup table.
    def subBytes(self, text):
        for i in range(0,16):
            text[i] = self.Sbox[text[i]]
        return text
    
    # same as subBytes but with inverse lookup table
    def dec_subBytes(self, text):
        for i in range(0,16):
            text[i] = self.Ibox[text[i]]
        return text
    
    # shift rows left
    def shiftRows(self, text):
        # text[0:4] does not change
        text[4:8] = text[5],text[6],text[7],text[4]
        text[8:12] = text[10],text[11],text[8],text[9]
        text[12:16] = text[15],text[12],text[13],text[14]
        return text
    
    # shift rows right
    def dec_shiftRows(self, text):
        # text[0:4] does not change
        text[4:8]=text[7],text[4],text[5],text[6]
        text[8:12]=text[10],text[11],text[8],text[9]
        text[12:16]=text[13],text[14],text[15],text[12]
        return text
    
    # combination of columns' bytes using Rijndael linear transformation
    # https://en.wikipedia.org/wiki/Rijndael_mix_columns
    def mixColumns(self, text):
        mixed=range(0,16)
        for i in range(0,4):
            mixed[0+i] = self.mul(2,text[0+i])^self.mul(3,text[4+i])^self.mul(1,text[8+i])^self.mul(1,text[12+i])
            mixed[4+i] = self.mul(1,text[0+i])^self.mul(2,text[4+i])^self.mul(3,text[8+i])^self.mul(1,text[12+i])
            mixed[8+i] = self.mul(1,text[0+i])^self.mul(1,text[4+i])^self.mul(2,text[8+i])^self.mul(3,text[12+i])
            mixed[12+i] = self.mul(3,text[0+i])^self.mul(1,text[4+i])^self.mul(1,text[8+i])^self.mul(2,text[12+i])
        return bytearray(mixed)
    
    # mix columns using inverse mixcolumns' table by Rijndael
    def dec_mixColumns(self,text):
        mixed=range(0,16)
        for i in range(0,4):
            mixed[0+i] = self.mul(14,text[0+i])^self.mul(11,text[4+i])^self.mul(13,text[8+i])^self.mul(9,text[12+i])
            mixed[4+i] = self.mul(9,text[0+i])^self.mul(14,text[4+i])^self.mul(11,text[8+i])^self.mul(13,text[12+i])
            mixed[8+i] = self.mul(13,text[0+i])^self.mul(9,text[4+i])^self.mul(14,text[8+i])^self.mul(11,text[12+i])
            mixed[12+i] = self.mul(11,text[0+i])^self.mul(13,text[4+i])^self.mul(9,text[8+i])^self.mul(14,text[12+i])
        return bytearray(mixed)
    
    # result = text XOR key
    def addRoundKey(self, text, key):
        result=[]
        for i in range(0,16):
            result.append(text[i] ^ key[i])
        return bytearray(result)
        
    # modified key_expand by @fredgj
    def expandKey(self,key):
        nr = (len(key)/4)+6 #rounds
        expanded = deepcopy(key)
        temp = [0]*4
        rcon_iter = 1
        size = len(key)    # key size in bytes
        # 11 keys needed 1 for pre-round tranformation and 10 other for 10 rounds (128bit key)
        size_expanded = (nr+1)*16
        size_current = size
        
        while size_current < size_expanded:
            for i in range(4):
                temp[i] = expanded[(size_current-4)+i]

            if (size_current%size)==0:
                temp = rotate(temp) # Rotation for Rijndael's key schedule
                for i in range(4):
                    temp[i] = self.Sbox[temp[i]]
                
                temp[0] = temp[0]^self.Rcon[rcon_iter]
                rcon_iter += 1
                
            # add an extra Sbox for 256 bit keys
            if (size_current%size)==16 and size==32:
                for i in range(4):
                    temp[i]= self.Sbox[temp[i]]

            for i in range(4):
                expanded.append(expanded[size_current-size]^temp[i])
                size_current += 1
                
        return expanded
    
    # PKCS5 padding from @pfote
    BLOCK_SIZE = 16

    def pkcs5_pad(self,s):
        """
        padding to blocksize according to PKCS #5
        calculates the number of missing chars to BLOCK_SIZE and pads with
        ord(number of missing chars)
        @see: http://www.di-mgt.com.au/cryptopad.html
        @param s: string to pad
        @type s: string
        @rtype: string
        """
        return s + (self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE) * chr(self.BLOCK_SIZE - len(s) % self.BLOCK_SIZE)

    def pkcs5_unpad(self,s):
        """
        unpadding according to PKCS #5
        @param s: string to unpad
        @type s: string
        @rtype: string
        """
        return s[0:-ord(s[-1])]

# Rotates a vector left so [a,b,c,d] => [b,c,d,a]
def rotate(vector):
    tmp = vector[0]

    for i in range(len(vector)-1):
        vector[i] = vector[i+1]

    vector[len(vector)-1] = tmp
    return vector
