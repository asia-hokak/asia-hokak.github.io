---
title: Classical Cipher
---

## Intro

>因為不想一直通靈所以打算做一篇古典密碼的筆記  

古典密碼通常會使用替換式或移項式的加密方式  
容易被頻率分析或暴力搜索破解  

## Substitution Cipher(替換式密碼)

字母位置不變，但透過以一個字母到兩個字母為一組，進行加密  
單表加密

### Casear Cipher(凱薩密碼)

![image](https://hackmd.io/_uploads/SyUMlq63C.png)  
會把每個字母同時位移  
比如說若`KEY = 1`  
`ABCDE` -> `BCDEF`  

script:

```python
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(plaintext:str, key:int)->str:
    cipher = ""
    for ch in plaintext:
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            ch = alphabet[(pos + key) % 26]
        cipher += ch
    return cipher

def decrypt(cipher:str, key:int)->str:
    plaintext = ""
    for ch in cipher:
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            ch = alphabet[(pos + key) % 26]
        plaintext += ch
    return plaintext

if __name__ == '__main__':
    cipher = encrypt('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 13)
    plaintext = decrypt(cipher, 13)
    print(cipher)
    print(plaintext)

```

### Vigenère Cipher(維吉尼亞密碼)

![image](https://hackmd.io/_uploads/ByBlqia20.png)
明文和金鑰都是字串，金鑰是循環的  
把金鑰的單個字元當作`offset`，`A`=0,`B`=1,`C`=2,etc.  

plaintext = `HELLO`  
key = `ABCD`  
cipher = `HFNOO`  

|plaintext|key|cipher|
|:-:|:-:|:-:|
|H|A|H|
|E|B|F|
|L|C|N|
|L|D|O|
|O|A|O|

script:

```python
from itertools import cycle
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(plaintext:str, key:str)->str:
    cipher = ""
    for ch, ch2 in zip(plaintext, cycle(key)):
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            offset = alphabet.index(ch2.upper())
            ch = alphabet[(pos + offset) % 26]
        cipher += ch
    return cipher

def decrypt(cipher:str, key:str)->str:
    plaintext = ""
    for ch, ch2 in zip(cipher, cycle(key)):
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            offset = alphabet.index(ch2.upper())
            ch = alphabet[(pos - offset) % 26]
        plaintext += ch
    return plaintext

if __name__ == '__main__':
    cipher = encrypt('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 'ABCD')
    plaintext = decrypt(cipher, 'ABCD')
    print(cipher)
    print(plaintext)
```

### Simple Substitution Cipher(簡易替換密碼)

![image](https://hackmd.io/_uploads/HyQ9pgC2R.png)
又稱Monoalphabetic Cipher(單表加密)  
用一張改變順序後的字母表，並以該字母表書寫  
即可稱為簡易替換密碼，像是凱薩加密、仿射加密都算

``` python
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def encrypt(plaintext:str, key:str)->str:
    cipher = ""
    for ch in plaintext:
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            ch = key[pos]
        cipher += ch
    return cipher

def decrypt(cipher:str, key:str)->str:
    plaintext = ""
    for ch in cipher:
        if ch.upper() in alphabet:
            pos = key.index(ch.upper())
            ch = alphabet[pos]
        plaintext += ch
    return plaintext

if __name__ == '__main__':
    key = 'GHAWQYKIJBXSTUVFOPCDRNMEZL'
    cipher = encrypt('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', key)
    plaintext = decrypt(cipher, key)
    print(cipher)
    print(plaintext)
```

### Affine Cipher(仿射加密)

![image](https://hackmd.io/_uploads/HJ-aLkAhR.png)  

加密:  

$$ a,m互質 $$
$$ E(x)=ax+b{\pmod {m}} $$

解密:  

$$ D(x)=a^{-1}(x-b){\pmod {m}}$$
$$ a^{-1} 為a對m之模倒數，\text{python中可以使用pow(a,-1,m)計算} $$

證明$E(x)$為單射函數:  

$$ E(x_1) = E(x_2) $$
$$ ax_1+b \equiv ax_2+b{\pmod {m}} $$
$$ ax_1 \equiv ax_2{\pmod {m}} $$
$$ x_1 \equiv x_2{\pmod {m}} $$
$$ x_1 = x_2(不超過字母表範圍) $$

script:

```python
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(plaintext:str, a:int, b:int)->str:
    cipher = ""
    for ch in plaintext:
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            ch = alphabet[(pos * a + b) % 26]
        cipher += ch
    return cipher

def decrypt(cipher:str, a:int, b:int)->str:
    plaintext = ""
    inv = pow(a, -1, 26)
    for ch in cipher:
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            ch = alphabet[(pos - b) * inv % 26]
        plaintext += ch
    return plaintext

if __name__ == '__main__':
    cipher = encrypt('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 15, 3)
    plaintext = decrypt(cipher, 15, 3)
    print(cipher)
    print(plaintext)
```

## Transposition Cipher(替換式加密)

字母不變，依某個順序替換每個字母的位置