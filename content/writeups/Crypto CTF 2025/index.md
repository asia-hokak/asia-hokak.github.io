---
title: Crypto CTF 2025
date: 2025-07-14
---

team:https://github.com/killua4564/2025-Crypto-CTF
latex 好像有點壞掉，可以看: https://hackmd.io/@hokak/CryptoCTF2025

## vinad

source

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from flag import flag

def parinad(n):
	return bin(n)[2:].count('1') % 2

def vinad(x, R):
	return int(''.join(str(parinad(x ^ r)) for r in R), 2)

def genkey(nbit):
	while True:
		R = [getRandomNBitInteger(nbit) for _ in range(nbit)]
		r = getRandomNBitInteger(nbit)
		p, q = vinad(r, R), getPrime(nbit)
		if isPrime(p):
			e = vinad(r + 0x10001, R)
			if GCD(e, (p - 1) * (q - 1)) == 1:
				return (e, R, p * q), (p, q)

def encrypt(message, pubkey):
	e, R, n = pubkey
	return pow(message + sum(R), e, n)

nbit = 512
pubkey, _ = genkey(nbit)
m = bytes_to_long(flag)
assert m < pubkey[2]
c = encrypt(m, pubkey)

print(f'R = {pubkey[1]}')
print(f'n = {pubkey[2]}')
print(f'c = {c}')
```
弱點在
```python
R = [getRandomNBitInteger(nbit) for _ in range(nbit)]
r = getRandomNBitInteger(nbit)
p, q = vinad(r, R), getPrime(nbit)
```
p是用r和R去生成的，但沒公開r，不過前面R使用了512次512的randombit生成  
所以可以用Randcrack來預測r

```python=
R = [...略]
n = 58113574203067314600162910771848744432179168354040678920098167335472534222998261639291145191568159464990603689062679467360303185717662426122140998218656632568172511390111887830539687208220100574329903748617343193392646019854280519859403817579746765861359633174218846216669659258251676438195667516224684805919
c = 56754194307199340085459028397027924827853574000671575387226403396873568994756738512141122143372650573201079937375922460851170745485734799044781029943783218210457587599666501326645229924138230588050782907693019958930006807017898115655426823272342984109999519420817119999272583495848119171867835187241510764427

import random, time
from randcrack import RandCrack
from Crypto.Util.number import *

def parinad(n):
    return bin(n)[2:].count('1') % 2

def vinad(x, R):
    return int(''.join(str(parinad(x ^ r)) for r in R), 2)

rc = RandCrack()

cnt = 0
for x in R[-39:]:
    for i in range(16):
        rc.submit(x % (1 << 32))
        x >>= 32

r = rc.predict_getrandbits(512)
p = vinad(r, R)
q = n // p
e = vinad(r + 0x10001, R)
d = pow(e, -1, (p-1)*(q-1))

print(long_to_bytes(pow(c, d, n) - sum(R)).decode())
# CCTF{s0lV1n9_4_Syst3m_0f_L1n3Ar_3qUaTi0n5_0vEr_7H3_F!3lD_F(2)!}
```

## tofee

source
```python
#!/usr/bin/env sage

import sys
from Crypto.Util.number import *
from hashlib import sha512
flag = b'test_flag'

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc():
	return sys.stdin.buffer.readline()

def sign(msg, skey):
    global k

    h = bytes_to_long(sha512(msg).digest())
    k = toffee(u, v, k)
    print(f'{k = }')
    print(int(k).bit_length())
    P = k * G
    r = int(P.xy()[0]) % _n
    s = inverse(k, _n) * (h + r * skey) % _n
    return (r, s)

def toffee(u, v, k):
	return (u * k + v) % _n

def main():
    border = "┃"
    pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    pr(border, ".:::    Welcome to the Toffee chocolate cryptography task!    ::.", border)
    pr(border, ".:  Your mission is to find flag by analyzing the signatures!  :.", border)
    pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    global flag, u, v, k, _n, G
    skey = bytes_to_long(flag)
    p = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41882ebea6f6e7b0e959d2c36ba5e27705daffacd9a49b39d5beedc74976b30a260c9
    a, b = -7, 0xd3f1356a42265cb4aec98a80b713fb724f44e747fe73d907bdc598557e0d96c5
    _n = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41881d942f0dddae61b0641e2a2cf144534c42bf8a9c3cb7bdc2a4392fcb2cc01ef87
    x = 0xa0e29c8968e02582d98219ce07dd043270b27e06568cb309131701b3b61c5c374d0dda5ad341baa9d533c17c8a8227df3f7e613447f01e17abbc2645fe5465b0
    y = 0x5ee57d33874773dd18f22f9a81b615976a9687222c392801ed9ad96aa6ed364e973edda16c6a3b64760ca74390bb44088bf7156595f5b39bfee3c5cef31c45e1
    F = FiniteField(p)
    E = EllipticCurve(F, [a, b])
    G = E(x, y)
    u, v, k = [randint(1, _n) for _ in ';-)']
    print(f"test: {u, v, k}")
    while True:
        pr(f"{border} Options: \n{border}\t[G]et toffee! \n{border}\t[S]ign message! \n{border}\t[Q]uit")
        ans = sc().decode().strip().lower()
        if ans == 'g':
            pr(border, f'Please let me know your seed: ')
            _k = sc().decode().strip()
            try:
                _k = int(_k)
            except:
                die(border, 'Your seed is not valid! Bye!!')
            pr(f'{toffee(u, v, _k) = }')
        elif ans == 's':
            pr(border, f'Please send your message: ')
            msg = sc().strip()
            print(msg)
            r, s = sign(msg, skey)
            
            pr(border, f'{r = }')
            pr(border, f'{s = }')
        elif ans == 'q':
            die(border, "Quitting...")
        else:
            die(border, "Bye...")

if __name__ == '__main__':
	main()
```

題目要我們recover私鑰skey
而這個簽章的k生成是使用LCG，且u和v可以透過`[G]et toffee!`獲得\

```python
def toffee(u, v, k):
	return (u * k + v) % _n
```

然後這題我有在AIS3 pre-exam 2025打過，所以後面我就搬之前的


$k = random$
$k_2 = uk + v$

我們知道
$s = k^{-1}(h+dr) \pmod n$
所以這邊可以假設收到的前組r、s有這樣的關係，而k並不是完全隨機

\begin{align}
k = s_1^{-1}h + s_1^{-1}dr_1 \pmod n\\
uk + v = s_2^{-1}h + s_2^{-1}dr_2 \pmod n
\end{align}


因為$a、b、r_1、r_2、s_1、s_2、h、n$已知
所以就變成一個聯立方程式，未知數為$k、d$
為了整理係數，我們把兩組方程式移項:

\begin{align}
k - s_1^{-1}dr_1 - s_1^{-1}h = 0 \pmod n\\
uk -  s_2^{-1}dr_2 - s_2^{-1}h  + v = 0 \pmod n
\end{align}

```python=
from pwn import *
from Crypto.Util.number import *
from sage.all import *
from hashlib import sha512

border = "┃"
options = f"{border} Options: \n{border}\t[G]et toffee! \n{border}\t[S]ign message! \n{border}\t[Q]uit"

io = remote('91.107.188.9', 31111)

def toffee(seed):
    io.sendlineafter(options, b'g')
    io.sendlineafter('Please let me know your seed: ', str(seed).encode())
    io.recvuntil(b'toffee(u, v, _k) = ')
    return int(io.recvline().strip().decode())
# (u * k + v) % _n


n = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41881d942f0dddae61b0641e2a2cf144534c42bf8a9c3cb7bdc2a4392fcb2cc01ef87

v = toffee(0)
u = (toffee(1) - v) % n
print(u, v)
assert (10000 * u + v) % n == toffee(10000)

F = GF(n)
R = PolynomialRing(F, names=('k', 'd'))  
k, d = R.gens()

message_hash = bytes_to_long(sha512(b'a').digest())
sigs = []
for i in range(2):
    io.sendlineafter(options, b's')
    io.sendlineafter(f'Please send your message: ', b'a')
    io.recvuntil(b'r = ')
    r = int(io.recvline().strip())
    io.recvuntil(b's = ')
    s = int(io.recvline().strip())
    sigs.append([message_hash, r, s])


def rng(x, y):
    for _ in range(y):
        x = (x*u + v)
    return x

P = []
for i, sig in enumerate(sigs):
    h, r, s = sig
    inv_s = pow(s, -1, n)
    P.append(inv_s * h + inv_s * d * r - rng(k, i))

M = Matrix(F, [
    [Pp.coefficient({k:1, d:0}), Pp.coefficient({k:0, d:1})]
    for Pp in P
])

V = Matrix(F, len(P), 1, [-Pp.coefficient({k:0, d:0}) for Pp in P])

sol = M.solve_right(V)
k = Integer(sol[0][0])
d = Integer(sol[1][0])

print(long_to_bytes(int(d)))
# CCTF{4fFin3Ly_r3lA7eD_n0nCE5_aR3_!n5eCuR3!}
```

## sobata

```python
#!/usr/bin/env sage

import sys
from Crypto.Util.number import *
from flag import FLAG

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc(): 
    return sys.stdin.buffer.readline()

def gen_params(nbit):
    while True:
        p = getPrime(nbit)
        if p % 6 == 1:
            F = GF(p)
            R = [F.random_element() for _ in '01']
            a, b = [R[_] ** ((p - 1) // (3 - _)) for _ in [0, 1]]
            if a != 1 and b != 1:
                c, d = [F.random_element() for _ in '01']
                E = EllipticCurve(GF(p), [0, d])
                return (p, E, a, b, c)

def walk(P, parameters):
    p, E, a, b, c = parameters
    x, y = P.xy()
    Q = (a * x, b * y)
    assert Q in E
    return int(c) * E(Q)

def jump(P, n, parameters):
    _parameters = list(parameters)
    _parameters[-1] = pow(int(_parameters[-1]), n, _parameters[1].order())
    return walk(P, _parameters)

def main():
    border = "┃"
    pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    pr(border, ".::               Welcome to the Sobata challenge!            ::. ", border)
    pr(border, " You should analyze this weird oracle and break it to get the flag", border)
    pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    nbit = 512
    parameters = gen_params(nbit)
    E = parameters[1]
    m = bytes_to_long(FLAG)
    assert m < parameters[0]
    while True:
        try:
            P = E.lift_x(m)
            break
        except:
            m += 1
    while True:
        pr("| Options: \n|\t[E]ncrypted FLAG \n|\t[W]alking with P \n|\t[J]umping over P \n|\t[Q]uit")
        ans = sc().decode().strip().lower()
        if ans == 'e':
            _P = walk(P, parameters)
            pr(border, f'The encrypted flag is: {_P.xy()}')
        elif ans == 'w':
            pr(border, 'Please send your desired point over E: ')
            Q = sc().decode().strip().split(',')
            try:
                Q = [int(_) for _ in Q]
            except:
                die(border, 'Your input is not valid!!')
            if Q in E:
                pr(border, f'The result of the walk is: {walk(E(Q), parameters).xy()}')
            else:
                die(border, 'Your point is not on the curve E! Bye!!')
        elif ans == 'j':
            pr(border, 'Send your desired point over E: ')
            Q = sc().decode().strip().split(',')
            pr(border, 'Let me know how many times you would like to jump over the given point: ')
            n = sc().decode().strip()
            try:
                Q = [int(_) for _ in Q]
                n = int(n)
            except:
                die(border, 'Your input is not valid!!')
            if Q in E:
                pr(border, f'The result of the jump is: {jump(E(Q), n, parameters).xy()}')
            else:
                die(border, 'Your point is not on the curve E! Bye!!')
        elif ans == 'q': die(border, "Quitting...")
        else: die(border, "Bye...")

if __name__ == '__main__':
    main()
```

這題要我們拿到生成元P的x值

```python
def walk(P, parameters):
    p, E, a, b, c = parameters
    x, y = P.xy()
    Q = (a * x, b * y)
    assert Q in E
    return int(c) * E(Q)

def jump(P, n, parameters):
    _parameters = list(parameters)
    _parameters[-1] = pow(int(_parameters[-1]), n, _parameters[1].order())
    return walk(P, _parameters)
```

jump 0的話$c$的值會是1  
也就是說我們可以拿到$ax$和$by$  
而$ax, by$也會再曲線上  
但會需要一點在曲線上的，我可以拿加密(walk)過後的G  
接下來拿$ax, ax^2, ax^3...ax^n\pmod p$  
對  
$ax \cdot ax^3-ax^2\cdot ax^2$  
$ax^2 \cdot ax^4-ax^3\cdot ax^3$  
$\vdots$  
$ax^{n-1}\cdot ax^{n+1}-ax^n \cdot ax^n$  
取GCD就可以得到$p$，後面就可以拿$a,b$和$d(y^2 - x^3 \equiv d \pmod p)$  
拿到這些曲線的參數之後可以嘗試去jump $\varphi(n) -1,n為曲線E的order$  
得到$c^{\varphi(n)-1}\equiv c^{-1}\pmod n$  
$\varphi(n)$的獲得難度取決於$n$的分解難度，不過基本上多送幾次就會有比較好分解的數了  

這題有更簡單的方法，不過我就不論述了killua大師應該會附  

```python
# %%
from pwn import *
from Crypto.Util.number import *
from sage.all import *
io = remote('91.107.133.165', 11177)

def str2point(s) -> tuple:
    l = [int(x) for x in s.strip()[1:-1].decode().split(',')]
    return tuple(l)

def jump(P, n):
    io.sendlineafter(options, b'j')
    io.sendlineafter(b'Send your desired point over E: ', str(P)[1:-1].encode())
    io.sendlineafter(b'Let me know how many times you would like to jump over the given point: ', str(n).encode())
    io.recvuntil(b'The result of the jump is: ')
    return str2point(io.recvline())

def walk(P):
    io.sendlineafter(options, b'w')
    io.sendlineafter(b'Please send your desired point over E: ', str(P)[1:-1].encode())
    io.recvuntil(b'The result of the walk is: ')
    return str2point(io.recvline())


options = b"| Options: \n|\t[E]ncrypted FLAG \n|\t[W]alking with P \n|\t[J]umping over P \n|\t[Q]uit"

io.sendlineafter(options, b'e')
io.recvuntil(b'The encrypted flag is: ')
F = str2point(io.recvline())

def get_params():
    jumped = []
    X = F
    for i in range(8):
        X = jump(X, 0)
        jumped.append(X)

    for i in range(1, 7):
        S = []
        aa = jumped[i][0]**2 - jumped[i - 1][0] * jumped[i + 1][0]
        bb = jumped[i][1]**2 - jumped[i - 1][1] * jumped[i + 1][1]
        S.append(abs(aa))
        S.append(abs(bb))
    
    p = GCD(S)
    a = pow(F[0], -1, p) * jumped[0][0] % p
    b = pow(F[1], -1, p) * jumped[0][1] % p
    d = (F[1] ** 2 - F[0] ** 3) % p
    
    assert F[0] * a % p == jumped[0][0]
    assert F[1] * b % p == jumped[0][1]
    return p, a, b, d

p, a, b, d = get_params()
E = EllipticCurve(GF(p), [0, d])
assert F in E
F = E(F)
n = E.order()
print(n)


# %%
phi = euler_phi(n)
print(phi)

# %%


P = E(F)
F_inv = (pow(a, -1, p) * P[0] % p, pow(b, -1, p) * P[1] % p)
assert F_inv[0] * a % p == P[0]
assert F_inv[1] * b % p == P[1]

print(P.xy())
Q = jump(F_inv, phi-1)
G = (pow(a, -1, p) * Q[0] % p, pow(b, -1, p) * Q[1] % p)
print(long_to_bytes(int(G[0])))
# CCTF{L1n3Ari7y_iN_w4lkIn9_ECC!}
```

## sobata II

```python=
#!/usr/bin/env sage

import sys, re
from Crypto.Util.number import *
from flag import FLAG

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc(): 
    return sys.stdin.buffer.readline()

def sanitize_string(inp):
    pattern = r'[^0-9g*+,]|[a-fh-zA-FH-Z]'
    return re.sub(pattern, '', inp)

def gen_params(nbit):
    while True:
        p = getPrime(nbit)
        R.<x> = PolynomialRing(GF(p))
        f = x^2 + 13 * x + 37
        f = R(f)
        if f.is_irreducible():
            F.<g> = GF(p^2, modulus = f)
            while True:
                a, b = [__ ** (__.multiplicative_order() // (3 - _)) for _, __ in enumerate(F.random_element() for _ in ':)')]
                if a.multiplicative_order() - 3 == b.multiplicative_order() - 2 == 0:
                    c, d = [randint(1, p) for _ in ':)']
                    E = EllipticCurve(F, [0, d])
                    return (p, F, E, a, b, c)

def walk(P, parameters):
    p, F, E, a, b, c = parameters
    x, y = P.xy()
    Q = (a * x, b * y)
    assert Q in E
    return int(c) * E(Q)

def jump(P, n, parameters):
    _parameters = list(parameters)
    _parameters[-1] = pow(int(_parameters[-1]), n, _parameters[1].order())
    return walk(P, _parameters)

def main():
    border = "┃"
    pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    pr(border, ".::             Welcome to the Sobata II challenge!           ::. ", border)
    pr(border, " You should analyze this weird oracle and break it to get the flag", border)
    pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    nbit = 196
    parameters = gen_params(nbit)
    p, F, E = parameters[0], parameters[1], parameters[2]
    g = F.gen()
    m = bytes_to_long(FLAG)
    assert m < p
    while True:
        try:
            P = E.lift_x(m + 1404 * g)
            break
        except:
            m += 1
    while True:
        pr("| Options: \n|\t[E]ncrypted FLAG \n|\t[W]alking with P \n|\t[J]umping over P \n|\t[Q]uit")
        ans = sc().decode().strip().lower()
        if ans == 'e':
            _P = walk(P, parameters)
            pr(border, f'The encrypted flag is: {_P.xy()}')
        elif ans == 'w':
            pr(border, 'Please send your desired point over E: ')
            Q = sc().decode().strip()
            Q = sanitize_string(Q).split(',')
            try:
                allowed_vars = {'g': g}
                Q = [eval(_, {'__builtins__': None}, allowed_vars) for _ in Q]
            except:
                die(border, 'Your input is not valid!!')
            if Q in E:
                pr(border, f'The result of the walk is: {walk(E(Q), parameters).xy()}')
            else:
                die(border, 'Your point is not on the curve E! Bye!!')
        elif ans == 'j':
            pr(border, 'Send your desired point over E: ')
            Q = sc().decode().strip()
            Q = sanitize_string(Q).split(',')
            pr(border, 'Let me know how many times you would like to jump over the given point: ')
            n = sc().decode().strip()
            try:
                allowed_vars = {'g': g}
                Q = [eval(_, {'__builtins__': None}, allowed_vars) for _ in Q]
                n = int(n)
            except:
                die(border, 'Your input is not valid!!')
            if Q in E:
                pr(border, f'The result of the jump is: {jump(E(Q), n, parameters).xy()}')
            else:
                die(border, 'Your point is not on the curve E! Bye!!')
        elif ans == 'q': die(border, "Quitting...")
        else: die(border, "Bye...")

if __name__ == '__main__':
    main()
```

這題就比較複雜了，是一個建立在多項式環$F_p$上的曲線，一樣要拿到生成元$P.x$  
我們可以用sobata的script改一下就可以拿到$a,b,p,d$的值  
前面$ax,ax^2...ax^n$的值換成一次項的係數  
不過這邊要注意$a$可能不只有常數，不過機率大概一半一半  
所以這邊就不寫專門對付$a$是多項式的情況了  

然後可以關注一下這題$c$的區間大概在$[1,p]$，不過E的階(這邊簡稱$n$)會來到$p^2$  
我們可以用pohlig-hellman來解這題  
而且只要分解後的質數取夠到$c$的bit length就好了  
複雜度會是$O(\sqrt{p_{max}})$，$p_{max}$是分解$n$最大質數  
理論上刷到約最大的p 50bits以內的都還算短  


```python
# %%
from pwn import *
from Crypto.Util.number import *
from sage.all import *
from tqdm import trange
# io = process(['sage', 'sobataii.sage'])

io = remote('91.107.161.140', 11173)
point_fmt = "{}*g + {}, {}*g + {}"
# context.log_level = 'debug'
def str2point(s) -> tuple:
    l = [x for x in s.strip()[1:-1].decode().split(',')]
    ret = [[int(x) for x in s.split('*g + ')] for s in l]
    return tuple(ret)

def jump(P, n):
    io.sendlineafter(options, b'j')
    io.sendlineafter(b'Send your desired point over E: ', str(point_fmt.format(P[0][0], P[0][1], P[1][0], P[1][1])).encode())
    io.sendlineafter(b'Let me know how many times you would like to jump over the given point: ', str(n).encode())
    io.recvuntil(b'The result of the jump is: ')
    return str2point(io.recvline())

def walk(P):
    io.sendlineafter(options, b'w')
    io.sendlineafter(b'Please send your desired point over E: ', str(point_fmt.format(P[0][0], P[0][1], P[1][0], P[1][1])).encode())
    io.recvuntil(b'The result of the walk is: ')
    return str2point(io.recvline())


options = b"| Options: \n|\t[E]ncrypted FLAG \n|\t[W]alking with P \n|\t[J]umping over P \n|\t[Q]uit"

io.sendlineafter(options, b'e')
io.recvuntil(b'The encrypted flag is: ')
EF = str2point(io.recvline())

def point2poly(p, g):
    return (p[0][0] * g + p[0][1], p[1][0] * g + p[1][1])

def get_params():
    jumped = []
    X = EF
    for i in trange(4):
        X = jump(X, 0)
        jumped.append(X)

    for i in range(1, 3):
        S = []
        aa = jumped[i][0][0]**2 - jumped[i - 1][0][0] * jumped[i + 1][0][0]
        bb = jumped[i][1][0]**2 - jumped[i - 1][1][0] * jumped[i + 1][1][0]
        S.append(abs(aa))
        S.append(abs(bb))
    
    p = GCD(S)
    a = pow(EF[0][0], -1, p) * jumped[0][0][0] % p
    b = pow(EF[1][0], -1, p) * jumped[0][1][0] % p
    R = PolynomialRing(GF(p), names=('x',))
    x = R.gen()
    f = x**2 + 13 * x + 37
    F = GF(p**2, name='g', modulus=f)
    g = F.gen()
    
    
    EF_poly = point2poly(EF ,g)
    d = (EF_poly[1] ** 2 - EF_poly[0] ** 3) % f
    
    assert EF[0][0] * a % p == jumped[0][0][0]
    assert EF[1][0] * b % p == jumped[0][1][0]
    return p, a, b, d, F

p, a, b, d, F = get_params()

print(a, b, d, p, F)
E = EllipticCurve(F, [0, d])
n = F.order()
print(n)
phi = euler_phi(n)
print(phi)

# %%

g = F.gen()
a = int(a)
b = int(b)
d = int(d)
p = int(p)


def point_devide_ab(P):
    return ([pow(a, -1, p) * P[0][0] % p, pow(a, -1, p) * P[0][1] % p], [pow(b, -1, p) * P[1][0] % p, pow(b, -1, p) * P[1][1] % p])

EF_inv = point_devide_ab(EF)
P = jump(EF_inv, 1)

ECC_EF = E(point2poly(EF, g))
P = E(point2poly(P, g))
print(ECC_EF)
print(P)


# nE = E.order()
# print(nE)



# %%

'''
from https://github.com/elikaski/ECC_Attacks?tab=readme-ov-file#The-order-of-the-generator-is-almost-a-smooth-number-and-the-private-key-is-small
'''
print("calc order")
G = ECC_EF
n = G.order()
print(n)

print("Number of bits in n:", n.nbits())
factors = n.factor()
print("n's factors:", factors)

PRIVATE_KEY_BIT_SIZE = 196

print("We know that the private key is", PRIVATE_KEY_BIT_SIZE, "bits long")
print("Lets find which of the factors of G's order are relevant for finding the private key")
# find factors needed such that the order is greater than the secret key size
count_factors_needed = 0
new_order = 1
for p, e in factors:
    new_order *= p**e
    count_factors_needed += 1
    if new_order.nbits() >= PRIVATE_KEY_BIT_SIZE:
        print("Found enough factors! The rest are not needed")
        break
factors = factors[:count_factors_needed]
print("Considering these factors:", factors)
maxPdigit = len(str(factors[-1][0]))
print(f"max P:{maxPdigit}")
    


print("Calculating discrete log for each quotient group...")
subsolutions = []
subgroup = []
for p, e in factors:
    quotient_n = (n // p ** e)
    G0 = quotient_n * G # G0's order is p^e
    P0 = quotient_n * P
    k = G0.discrete_log(P0)
    print(k)
    subsolutions.append(k)
    subgroup.append(p ** e) # k the order of G0

print("Running CRT...")
c = crt(subsolutions, subgroup)
assert c * G == P
print(f"{c=}")



# %%
E = EllipticCurve(F, [0, d])
n = E.order()
phi = euler_phi(n)

# for test
inv_c = pow(c, phi-1, n)
G = E.random_element()
print(G)
Q = G*c
print(Q)
Q = Q*int(inv_c)
print(Q)
```

因為很難刷到c，所以不太確定接下來的script能不能順利跑好  
所以我把接下來的參數放到另外一個script上面跑
```python=
from sage.all import *
from Crypto.Util.number import *
a,b,d,p=(27415078278705943173248686032762859913892271126336088495674,85343696207682507463081995581530292664549906625552217251278,84412988527328974803317456556577950631753400831095577228135,85343696207682507463081995581530292664549906625552217251279)
R = PolynomialRing(GF(p), names=('x',))
x = R.gen()
f = x**2 + 13 * x + 37
F = GF(p**2, name='g', modulus=f)
g = F.gen()
c = 81446674977834806094264227703761537144469572604059356266599

E = EllipticCurve(F, [0, d])
n = E.order()
phi = euler_phi(n)

EF = E(80105022105305656435804001786978544483063554811387226742138*g + 45822344950548198179313350724637284119435282504928250868227 , 27573977151832639255987910477162487928036614614340701345896*g + 48512223005936495900657109299888518641240949701285562336657)
P = E(59959918177806095898859935476069121486342386709716822159338*g + 48979991981825255322488301826955724311410886171452523085602 , 68442194321836907018203511649392289039628198892210668492569*g + 1399470228127443028376163429743970271950998458273667227608)

inv_c = pow(c, -1, n)
F = EF*int(inv_c)
ax = F.xy()[0].polynomial().coefficients()[0]
print(long_to_bytes(int(ax) * pow(int(a), -1, p) % p))
# CCTF{Ecc_5tRong_cRyPto!}
```