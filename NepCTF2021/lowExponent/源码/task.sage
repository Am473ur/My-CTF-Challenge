from Crypto.Util.number import *
from secret import flag

def Encrypt(e, nbits, msg):
    p, q = [getPrime(int(nbits)) for _ in range(2)]
    N = p*q
    x = int(msg)
    while True:
        a, b = [getRandomRange(1, N) for _ in range(2)]
        P.<Yp> = PolynomialRing(Zmod(p))
        fp = x^3 + a*x + b - Yp^2
        P.<Yq> = PolynomialRing(Zmod(q))
        fq = x^3 + a*x + b - Yq^2
        try:
            yp, yq = int(fp.roots()[0][0]), int(fq.roots()[0][0])
            y = crt([yp, yq], [p, q])
            E = EllipticCurve(IntegerModRing(N), [a, b])
            msg_point = E.point((x, y))
            Ep = EllipticCurve(IntegerModRing(p), [a, b])
            Eq = EllipticCurve(IntegerModRing(q), [a, b])
            N1 = Ep.order()
            N2 = 2*p+2-N1
            N3 = Eq.order()
            N4 = 2*q+2-N3
            d = {
                ( 1, 1): inverse_mod(e, lcm(N1, N3)),
                ( 1,-1): inverse_mod(e, lcm(N1, N4)),
                (-1, 1): inverse_mod(e, lcm(N2, N3)),
                (-1, -1): inverse_mod(e, lcm(N2, N4))
            }
            break
        except:
            pass
    cip_point = e*msg_point
    ciphertext = cip_point.xy()[0]
    privKey = (d, p, q)
    pubKey = (a, b, N)
    return (ciphertext, pubKey, privKey)

def Decrypt(ciphertext, pubKey, privKey):
    d, p, q = privKey
    a, b, N = pubKey
    x = ciphertext
    w = x^3 + a*x + b % N
    P.<Yp> = PolynomialRing(Zmod(p))
    fp = x^3 + a*x + b -Yp^2
    yp = fp.roots()[0][0]
    P.<Yq> = PolynomialRing(Zmod(q))
    fq = x^3 + a*x + b -Yq^2
    yq = fq.roots()[0][0]
    y = crt([int(yp), int(yq)], [p, q])
    E = EllipticCurve(IntegerModRing(N), [a, b])
    cip_point = E.point([x, y])
    legendre_symbol_p = legendre_symbol(w, p)
    legendre_symbol_q = legendre_symbol(w, q)
    msg_point = d[(legendre_symbol_p, legendre_symbol_q)]*cip_point
    return msg_point.xy()[0]


msg = bytes_to_long(flag)
f = open("data", "w")
for i in range(70):
    current_st = time()
    cipher = Encrypt(3, 256, msg)
    f.writelines("{}, {}, {}, {}\n".format(cipher[0],*cipher[1]))
f.close()
