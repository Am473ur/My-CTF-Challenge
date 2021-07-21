from Crypto.Util.number import getPrime
from random import randint

Int = [3, 11, 19, 67, 163]
Num = 1000000
Cnt = 0
for i in range(Num):
    if getPrime(randint(2, 8)) in Int:
        Cnt += 1
print(Cnt/Num)
N = 1444329727510154393553799612747635457542181563961160832013134005088873165794135221
