from functools import reduce
from Crypto.Util.number import *

f = open("data", "r")
ciphertext = []
a, b, n = [], [], []
for i in range(70):
    ci, ai, bi, ni = [int(num) for num in f.readline().strip().split(", ")]
    ciphertext.append(ci)
    a.append(ai)
    b.append(bi)
    n.append(ni)

e = 3
deg = 9
coeffi = []
for i in range(70):
    E = EllipticCurve(IntegerModRing(n[i]), [a[i], b[i]])
    P.<m> = PolynomialRing(Zmod(n[i]))
    f = ciphertext[i]*E._multiple_x_denominator(e, m) - E._multiple_x_numerator(e, m)
    coeffi.append(f.coefficients(sparse=False))

# f.coefficients(sparse=False) 从低位到高位输出多项式的系数（0也输出）
large_coeffi = [crt([int(coeffi[j][i]) for j in range(70)], [n[j] for j in range(70)]) for i in range(deg+1)]
N_bitlength = sum([n[i].bit_length() for i in range(70)])
print(f"bit length of N: {N_bitlength}")
print([(N_bitlength-int(11*n[i]).bit_length()) for i in range(deg+1)])
print([int(large_coeffi[i]).bit_length() for i in range(deg+1)])
min_n = min(n)
N = reduce(lambda x, y: x*y, n)


Sc = large_coeffi
var("x")
assume(x, 'integer')
f = Sc[9]*x^9+Sc[8]*x^8+Sc[7]*x^7+Sc[6]*x^6+Sc[5]*x^5+Sc[4]*x^4+Sc[3]*x^3+Sc[2]*x^2+Sc[1]*x+Sc[0]


lat = []
lat.append([large_coeffi[i]*min_n**i for i in range(deg+1)]+[1/(deg+1)])
for i in range(deg+1):
    lat.append([((min_n**j)*N if (i==j) else 0) for j in range(deg+1)]+[0])
Mat = matrix(lat)
Mat_LLL = Mat.LLL()
for lin in range(deg):
    Sc = [int(i) for i in Mat_LLL[lin]]
    print([(Sc[i]%(min_n**i)==0) for i in range(deg+1)])
    Sc = [(Sc[i]//(min_n**i)) for i in range(deg+1)]
    print(f"bit length of N: {N_bitlength}")
    print("#################### Before LLL ####################")
    print([(N_bitlength-int(11*n[i]).bit_length()) for i in range(deg+1)])
    print([int(large_coeffi[i]).bit_length() for i in range(deg+1)])
    print("#################### After LLL ####################")
    print([(N_bitlength-int(11*n[i]).bit_length()) for i in range(deg+1)])
    print([int(Sc[i]).bit_length() for i in range(deg+1)])

    var("x")
    assume(x, 'integer')
    f = Sc[9]*x^9+Sc[8]*x^8+Sc[7]*x^7+Sc[6]*x^6+Sc[5]*x^5+Sc[4]*x^4+Sc[3]*x^3+Sc[2]*x^2+Sc[1]*x+Sc[0]
    print(factor(f))
    break
'''
m = 3088969433059681806521206959873975785377227976800172674306727155831805513908352148702210247662586117242206183337522557
print(long_to_bytes(m))
'''