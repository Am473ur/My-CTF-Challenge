from PIL import Image
import numpy as np
from Crypto.Util.number import *
import random
from gmpy2 import lcm
from secret import flag


def getMyPrime(nbits):
    def genProduct(nbits):
        p = 1
        while p.bit_length() < nbits:
            p *= random.choice(sieve_base)
        return p
    P = genProduct(nbits)
    while not isPrime(P-1):
        P = genProduct(nbits)
    return (P-1)


class Homo:
    def __init__(self):
        p, q = getMyPrime(512), getMyPrime(512)
        n = p*q
        g = random.randint(1, n*n)
        while GCD(self.L(pow(g, lcm(p-1, q-1), n*n), n), n) != 1:
            g = random.randint(1, n*n)
        self.g, self.n = g, n
        print("n =", n)
        print("g =", g)

    def enc(self, m):
        n = self.n
        return (pow(self.g, int(m), n*n)*pow(random.randint(1, n), n, n*n)) % (n*n)

    def L(self, u, n): return (u-1)//n


def encrypt_img(homo, img_array):
    cip_list = []
    for i in range(len(img_array)):
        for j in range(len(img_array[i])):
            cip_list.append(homo.enc(img_array[i][j]))
    return cip_list


def encrypt_flag(homo, flag):
    flag_bin = bin(flag)[2:]
    cip_list = [homo.enc(int(i) << 8) for i in flag_bin]
    return cip_list


if __name__ == "__main__":
    homo = Homo()
    img = Image.open("./img.png").convert("L") # 56x56
    img_array = np.array(img)
    img_enc = encrypt_img(homo, img_array)
    flag = bytes_to_long(flag.encode())
    flag_enc = encrypt_flag(homo, flag)
    
    assert len(img_enc) > len(flag_enc)
    with open("data", "w") as f:
        for i in range(len(img_enc)):
            if i < len(flag_enc):
                enc = (flag_enc[i]*img_enc[i]) % (homo.n**2)
                f.write(hex(enc)[2:]+"\n")
            else:
                f.write(hex(img_enc[i])[2:]+"\n")

# n = 18434491463536053807355381425234564739214857081161321309756933006496704225386021314592003940717664842835425875706674652882353813796736161102105318696602774157554627232038142092845118667433422811370679163251506433284182749390704212211677891535882993540750379419384629735499044085104591893176847835387567644762636961
# g = 99894228586367782940715460732971967417359410558715186789679488951080212107512884192976002563404881263875114900183845944243751294600634946131559701908524899495387780188074842981190381617301097312646907480816373003121403029154865843313001145153263200356271270964096284006748227606839491672635131818273934109984977288621523498782962389115299664149676881349445940131040928322172748228670542470966453917916224551852329336572423059849239115479150176538160893340622774682474615303826972971312087884483400100816655408278649954266707268236152380355955111697822333005733513834283677509165970313043388621472231706074701389916165894223877
