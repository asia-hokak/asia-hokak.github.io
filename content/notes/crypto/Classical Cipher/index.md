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

#### 加密

會把每個字母同時位移  
比如說若`KEY = 1`  
`ABCDE` -> `BCDEF`  

|項目|值|
|-|-|
|明文|THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG|
|密鑰|13|
|密文|GUR DHVPX OEBJA SBK WHZCF BIRE GUR YNML QBT|


#### 解密

反過來做就好了

#### 實作

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
明文和都是字串，密鑰是循環的  

#### 加密

把密鑰的單個字元當作`offset`，`A`=0,`B`=1,`C`=2,etc.  
|項目|值|
|-|-|
|明文|THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG|
|密鑰|ABCD|
|密文|TIG TUJEN BSQZN GQA JVOSS PXHR UJH LBBB DPI|

#### 解密

反過來做就好了

#### 實作

```python
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(plaintext:str, key:str)->str:
    cipher = ""
    key_pos = 0
    for ch in plaintext:
        ch2 = key[key_pos % len(key)]
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            offset = alphabet.index(ch2.upper())
            ch = alphabet[(pos + offset) % 26]
            key_pos += 1
        cipher += ch
    return cipher

def decrypt(cipher:str, key:str)->str:
    plaintext = ""
    key_pos = 0
    for ch in cipher:
        ch2 = key[key_pos % len(key)]
        if ch.upper() in alphabet:
            pos = alphabet.index(ch.upper())
            offset = alphabet.index(ch2.upper())
            ch = alphabet[(pos - offset) % 26]
            key_pos += 1
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

#### 加密

把明文的每個字母替換成對照表對應的字母

|項目|值|
|-|-|
|明文|THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG|
|密鑰|GHAWQYKIJBXSTUVFOPCDRNMEZL|
|密文|DIQ ORJAX HPVMU YVE BRTFC VNQP DIQ SGLZ WVK|

#### 解密

反過來做就好了

#### 實作

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

### Affine Cipher(仿射密碼)

![image](https://hackmd.io/_uploads/HJ-aLkAhR.png)  

#### 加密

$$ a,m互質 $$
$$ E(x)=ax+b{\pmod {m}} $$


|項目|值|
|-|-|
|明文|THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG|
|密鑰|`a`=15, `b`=3|
|密文|CEL JRTHX SYFVQ AFK IRBUN FGLY CEL MDOZ WFP|

證明加密的可行性: $E(x)$為單射函數
$$ E(x_1) = E(x_2) $$
$$ ax_1+b \equiv ax_2+b{\pmod {m}} $$
$$ ax_1 \equiv ax_2{\pmod {m}} $$
$$ x_1 \equiv x_2{\pmod {m}} $$
$$ x_1 = x_2(不超過字母表範圍) $$

#### 解密  

$$ D(x)=a^{-1}(x-b){\pmod {m}}$$
$$ a^{-1} 為a對m之模倒數，\text{python中可以使用pow(a,-1,m)計算} $$

解密原理:
$$ D(x)=a^{-1}(E(x)-b){\pmod {m}}$$
$$ D(x)=a^{-1}(ax+b-b){\pmod {m}}$$
$$ D(x)=a^{-1}a^{1}x{\pmod {m}}$$
$$ D(x)=x{\pmod {m}}$$

#### 實作

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

### Scytale Cipher(密碼棒)

![image](https://hackmd.io/_uploads/HJadE8gaC.png)

#### 加密

把字條綁在指定寬度的木棒上，並橫著書寫文字  

|項目|值|
|-|-|
|明文|THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG|
|密鑰|5|
|密文|TUB J  LDHIRFUOTAOECOOMVHZG KWXPEEY Q N SR |


#### 解密

把紙條綁在指定寬度的木棒上，橫著閱讀文字

#### 實作

```python=
def encrypt(plaintext, key):
    plaintext += ' ' * (-len(plaintext) % key)
    cipher = [''] * key
    for i, ch in enumerate(plaintext):
        cipher[i % key] += ch
    return ''.join(cipher)

def decrypt(cipher, key):
    cipher += ' ' * (-len(cipher) % key)
    row = len(cipher) // key
    plaintext = [''] * row
    for i, ch in enumerate(cipher):
        plaintext[i % row] += ch
    return ''.join(plaintext)

if __name__ == '__main__':
    cipher = encrypt('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 5)
    plaintext = decrypt(cipher, 5)
    print(cipher.encode())
    print(plaintext)
```

### Railfence Cipher

#### 加密

![image](https://hackmd.io/_uploads/SkTg_UeT0.png)

如上圖，把文字依這種格式排列  
並橫著書寫文字

|項目|值|
|-|-|
|明文|THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG|
|密鑰|5|
|密文|TKFSHDHC  OP TE OEIBNXMO  YG URW UVRLZQOJEA|


#### 解密

推算回書寫的格式，並依照上圖順序閱讀

#### 實作

```python=
def encrypt(plaintext:str, key:int)->str:
    rails = [''] * key
    rail = 0
    dir = 1

    for char in plaintext:
        rails[rail] += char
        if rail == 0:
            dir = 1
        elif rail == key - 1:
            dir = -1
        rail += dir

    return ''.join(rails)

def decrypt(ciphertext:str, key:int):
    rails = [[] for _ in range(key)]
    rail_len = [0] * key
    rail = 0
    dir = 1

    for i in range(len(ciphertext)):
        rail_len[rail] += 1
        if rail == 0:
            dir = 1
        elif rail == key - 1:
            dir = -1
        rail += dir

    idx = 0
    for i in range(key):
        rails[i] = list(ciphertext[idx:idx + rail_len[i]])
        idx += rail_len[i]

    decrypted_text = []
    rail = 0
    dir = 1
    for i in range(len(ciphertext)):
        decrypted_text.append(rails[rail].pop(0))
        if rail == 0:
            dir = 1
        elif rail == key - 1:
            dir = -1
        rail += dir

    return ''.join(decrypted_text)

if __name__ == '__main__':
    cipher = encrypt('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 5)
    plaintext = decrypt(cipher, 5)
    print(cipher)
    print(plaintext)
```
