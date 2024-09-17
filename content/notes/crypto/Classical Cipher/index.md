---
title: Classical Cipher
---

Intro
---

>因為不想一直通靈所以打算做一篇古典密碼的筆記  

古典密碼通常會使用替換式或移項式的加密方式  
容易被頻率分析或暴力搜索破解  

Substitution Cipher(替換式密碼)
---

字母位置不變，但透過以一個字母到兩個字母為一組，進行加密  

### Casear Cipher(凱薩密碼)

---

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

反過來做就好了，這種加密方式很容易爆破

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

---

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

密碼破譯，[工具](https://planetcalc.com/7956/):  
1. 卡西斯基試驗:當相同的字母序列在密文中重複出現，中間的間隔可能是密鑰長度
2. 弗里德曼試驗:密文中的字母會出現不同頻率，可以通過計算密文的重合指數，來獲得密鑰長度  

---

重和指數:  
$$
\kappa_{o} = \frac{\sum_{i=1}^{c}n_{i}(n_{i}-1)}{N(N-1)}
$$  
$c$:字母表的長度（英文為26）  
$N$:指文本的長度  
$n_1$~$n_c$:密文的字母頻率，為整數  

密鑰長度約為:
$${\kappa _{p}-\kappa _{r}} \over {\kappa _{o}-\kappa _{r}}$$
${\kappa _{p}}$:兩個任意字母相同的概率  
${\kappa _{r}}$:字母表中這種情況出現的概率（英文中為1/26=0.0385)  

---
3. 頻率分析，一旦確定密鑰長度，可以把密文分成和密鑰長度相等的列數，一列相等於一組凱薩密碼，透過頻率分析可以獲得明文


#### 實作

```python
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(plaintext:str, key:int)->str:
    cipher = ""
    for ch in plaintext.upper():
        if ch.isalpha():
            pos = alphabet.index(ch)
            ch = alphabet[(pos + key) % 26]
        cipher += ch
    return cipher

def decrypt(cipher:str, key:int)->str:
    plaintext = ""
    for ch in cipher.upped():
        if ch.isalpha():
            pos = alphabet.index(ch)
            ch = alphabet[(pos + key) % 26]
        plaintext += ch
    return plaintext

if __name__ == '__main__':
    cipher = encrypt('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 13)
    plaintext = decrypt(cipher, 13)
    print(cipher)
    print(plaintext)
```

### Simple Substitution Cipher(簡易替換密碼)

---

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

反過來做就好了，也可以使用[quip qiup](https://quipqiup.com/)爆破

#### 實作

``` python
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(plaintext:str, key:str)->str:
    cipher = ""
    for ch in plaintext.upper():
        if ch.isalpha():
            pos = alphabet.index(ch)
            ch = key[pos]
        cipher += ch
    return cipher

def decrypt(cipher:str, key:str)->str:
    plaintext = ""
    for ch in cipher.upper():
        if ch.isalpha():
            pos = key.index(ch)
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

---

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

也可以使用[quip qiup](https://quipqiup.com/)爆破

#### 實作

```python
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(plaintext:str, a:int, b:int)->str:
    cipher = ""
    for ch in plaintext:
        if ch.isalpha():
            pos = alphabet.index(ch.upper())
            ch = alphabet[(pos * a + b) % 26]
        cipher += ch
    return cipher

def decrypt(cipher:str, a:int, b:int)->str:
    plaintext = ""
    inv = pow(a, -1, 26)
    for ch in cipher:
        if ch.isalpha():
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

### Playfair Cipher

---

#### 加密

*密鑰產生*  
1. 選取一個英文字作密鑰
2. 除去重覆出現的字母
3. 將密鑰的字母逐個逐個加入5×5的矩陣內，剩下的空間將未加入的英文字母依a-z的順序加入（將Q去除，或將I和J視作同一字）  

假設密鑰為`PLAYFAIR EXAMPLE`  
![image](https://hackmd.io/_uploads/BJt5btl60.png)  

*預處理*  
將每兩個字母分成一組，若是同組字母一樣，在兩字母之間插入`X`或`Q`，重新分組，若剩下一個字，在尾端補上`X`

`Hide the gold in the tree stump` ->`HI DE TH EG OL DI NT HE TR EX ES TU MP`  

*加密*  
找出組中兩個字母的位置  
1. 字母不同行不同列，取對角的字元  
![image](https://hackmd.io/_uploads/SklZHtgTR.png)
2. 字母同行，取兩字母右方之字元  
![image](https://hackmd.io/_uploads/B1jrBteaR.png)
3. 字母同列，取兩字母下方之字元  
![image](https://hackmd.io/_uploads/B15FrYeaC.png)

|項目|值|
|-|-|
|明文|HIDE THE GOLD IN THE TREE STUMP|
|密鑰|PLAYFAIR EXAMPLE|
|密文|BM OD ZB XD NA BE KU DM UI XM MO UV IF|

#### 解密

將加密過程反過來操作即可，但字元會因為經過預處理過的關係，導致和明文有所偏差


#### 實作

```python
def gen_key(key:int):
    key = key.replace('J', 'I')
    matrix = []
    used = set()
    
    for ch in key.upper():
        if ch not in used and ch.isalpha():
            matrix.append(ch)
            used.add(ch)

    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in used:
            matrix.append(ch)
            used.add(ch)

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix:list, ch:str):
    for y in range(5):
        for x in range(5):
            if matrix[y][x] == ch:
                return y, x
    return None

def preprocess_text(text:str):
    text = text.replace('J', 'I').upper().replace(' ', '')
    processed = ""
    
    i = 0
    while i < len(text):
        ch = text[i]
        ch2 = text[i+1] if i+1 < len(text) else 'X'

        if ch == ch2:
            processed += ch
            processed += 'X'
            i += 1
        else:
            processed += ch
            processed += ch2
            i += 2

    return processed

def encrypt(plaintext:str, key:str):
    matrix = gen_key(key)
    plaintext = preprocess_text(plaintext)

    cipher = []
    for i in range(0, len(plaintext), 2):
        ch1, ch2 = plaintext[i], plaintext[i+1]
        y1, x1 = find_position(matrix, ch1)
        y2, x2 = find_position(matrix, ch2)

        if y1 == y2:
            cipher += matrix[y1][(x1 + 1) % 5]
            cipher += matrix[y2][(x2 + 1) % 5]
        elif x1 == x2:
            cipher += matrix[(y1 + 1) % 5][x1]
            cipher += matrix[(y2 + 1) % 5][x2]
        else:
            cipher += matrix[y1][x2]
            cipher += matrix[y2][x1]

    return ''.join(cipher)

def decrypt(cipher, key):
    matrix = gen_key(key)
    plaintext = []
    
    for i in range(0, len(cipher), 2):
        y1, x1 = find_position(matrix, cipher[i])
        y2, x2 = find_position(matrix, cipher[i+1])

        if y1 == y2:
            plaintext.append(matrix[y1][(x1 - 1) % 5])
            plaintext.append(matrix[y2][(x2 - 1) % 5])
        elif x1 == x2:
            plaintext.append(matrix[(y1 - 1) % 5][x1])
            plaintext.append(matrix[(y2 - 1) % 5][x2])
        else:
            plaintext.append(matrix[y1][x2])
            plaintext.append(matrix[y2][x1])

    return ''.join(plaintext)

if __name__ == '__main__':
    cipher = encrypt('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 'PLAYFAIR EXAMPLE')
    plaintext = decrypt(cipher, 'PLAYFAIR EXAMPLE')
    print(cipher)
    print(plaintext)

```

Transposition Cipher(替換式加密)
---

字母不變，依某個順序替換每個字母的位置

### Scytale Cipher(密碼棒)

---

![image](https://hackmd.io/_uploads/HJadE8gaC.png)  

#### 加密

把字條綁在指定寬度的木棒上，並橫著書寫文字  

|項目|值|
|-|-|
|明文|THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG|
|密鑰|5|
|密文|TUB J  LDHIRFUOTAOECOOMVHZG KWXPEEY Q N SR |


#### 解密

把紙條綁在指定寬度的木棒上，橫著閱讀文字，很容易爆破

#### 實作

```python
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

---

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

推算回書寫的格式，並依照上圖順序閱讀，很容易爆破

#### 實作

```python
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

### Route Cipher

---

![image](https://hackmd.io/_uploads/HymU_tlp0.png)  


#### 加密

將明文再給定尺寸的網格寫下，在依照特定的路徑讀取字母

|項目|值|
|-|-|
|明文|WE ARE DISCOVERED FLEE AT ONCE|
|密鑰|「從右上角開始，順時針向內螺旋讀取」|
|密文|EJXCTEDEC DAEWRIORF EONALEVSE|

#### 解密

依照密鑰的指令，反方向寫回給定尺寸的網格
