import hashlib
import string
import sys
from functools import reduce

from Crypto.Util.number import *
from gmpy2 import invert
from pwn import *

HOST = "42.192.180.50"
POST = 30004
r = remote(HOST, POST)
sys.setrecursionlimit(10**6)


def proof_of_work():
    rev = r.recvuntil("sha256(XXXX+")
    suffix = r.recv(16).decode()
    rev = r.recvuntil(" == ")
    tar = r.recv(64).decode()

    def f(x):
        hashresult = hashlib.sha256(x.encode()+suffix.encode()).hexdigest()
        return hashresult == tar

    prefix = util.iters.mbruteforce(
        f, string.digits + string.ascii_letters, 4, 'upto')
    r.recvuntil("Give me XXXX:")
    r.sendline(prefix)


def qicheng(n: int):
    R = Integers(n)
    js = [0, (-2 ^ 5) ^ 3, (-2 ^ 5*3) ^ 3, (-2 ^ 5*3*5*11) ^ 3, (-2 ^ 6*3*5*23*29) ^ 3]
    p, q = None, None
    for _ in range(20):
        for j in js:
            if j == 0:
                a = R.random_element()
                E = EllipticCurve([0, a])
            else:
                a = R(j)/(R(1728)-R(j))
                c = R.random_element()
                E = EllipticCurve([3*a*c ^ 2, 2*a*c ^ 3])

            x = R.random_element()
            z = E.division_polynomial(n, x)
            g = gcd(z, n)
            if g > 1:
                p = Integer(g)
                q = Integer(n)//p
                break
        if p:
            break
    return (p, q)


proof_of_work()
r.recvuntil(b"n = ")
n = int(r.recvline().strip().decode())
r.recvuntil(b"e = ")
e = int(r.recvline().strip().decode())
r.recvuntil(b"c = ")
c = int(r.recvline().strip().decode())
p, q = qicheng(n)
secret = pow(c, inverse_mod(e, (p-1)*(q-1)), n)
r.sendline(b"1")
r.recvuntil(b"> ")
r.sendline(str(secret).encode())
r.interactive()
