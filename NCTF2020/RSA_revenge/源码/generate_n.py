from Crypto.Util.number import *
import os
Int = [3, 11, 19, 43, 67, 163]
def getp(nbits):
    b = getRandomNBitInteger(nbits)
    p4 = 427*b*b+1
    while p4%4 or not isPrime(p4//4):
        b = getRandomNBitInteger(nbits)
        p4 = 427*b*b+1
    return p4//4
p = getp(128)
N = p*getPrime(p.bit_length())
print(N)
print(N.bit_length())
