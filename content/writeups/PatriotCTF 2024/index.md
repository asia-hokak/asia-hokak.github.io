---
title: PatriotCTF 2024
---

## Intro

### ranking

![image](https://hackmd.io/_uploads/Bk231h70A.png)

團隊總排名`33/1360`|`TOP 2%`

### solves(personal)

|Category|solves|
|:-:|:-:|
|Crypto|4/10|
|Reverse|2/10|

![image](https://hackmd.io/_uploads/ByHEx3QCA.png)
我跟隊友說好我要打Crypto然後我就真的只去戳Crypto  
結果居然沒讓我算到數學，幾乎打得都是對稱加密QwQ  
最後看Reverse好像解題數有點少就去幫忙消化幾題  
在解的過程中，隊伍一度衝到前30

![image](https://hackmd.io/_uploads/BkgXZnmAC.png)  
其實我原本應該是會去打pwn的，但時間已經很晚了  
雖然看到pwn的解題數還是很低，不過為了我的肝我就不碰了  
這次的題目我覺得出得很棒，學到了很多酷東西  

## Crypto

### Hard to implement

#### 加密

重複多次

|||
|:-:|-|
|encryption|AES(ECB_MODE, 128bits)|
|data|`user_input` + `flag`|

#### 解法

AES prepend oracle:  

假設使用者輸入`000000000000000`  
密文的第一個block會是`000000000000000` + `flag的第一個字`  
輸入`00000000000000`  
密文的第一個block則會是`00000000000000` + `flag的前兩個字`  

於是我們可以透過窮舉最後一個字元，並驗證密文是否相等  
`000000000000000a`  
`000000000000000b`  
`000000000000000c`  
...  
`000000000000000p`  
以此類推其他求出接下來的字元  
`00000000000000pa`  
`00000000000000pb`  
...

solve:
```python
from pwn import *
from tqdm import *
r = remote('chal.competitivecyber.club', 6002)

pretends = []
for i in range(15, 1, -1):
    r.sendlineafter(b'Send challenge > ' ,b'0' * i)
    r.recvuntil(b'Response > ')
    pretend = bytes.fromhex(r.recv(32).decode())
    pretends.append(pretend)

oracle = b''
for i, pretend in enumerate(pretends):
    for byte in trange(0x20, 0x7f):
        payload = b'0' * (15 - i) + oracle + bytes([byte])
        r.sendlineafter(b'Send challenge > ' , payload)
        r.recvuntil(b'Response > ')
        response = bytes.fromhex(r.recv(32).decode())
        if response == pretend:
            oracle += bytes([byte])
            print(oracle.decode())
            break
```

### High Roller

#### 加密

用時間當seed，生成公私鑰，並寫出到一個`.pem`檔
![image](https://hackmd.io/_uploads/SyTEoBZR0.png)

#### 解法

可以透過`檔案的最後修改時間`獲得seed  
solve:
```python
import os
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import random

filetime = os.path.getmtime("public_key.pem")

with open("public_key.pem", "rb") as key_file:
    public_key = RSA.import_key(key_file.read())

origin_N = public_key.n
e = public_key.e
d = 0

random.seed(int(filetime))
p, q = getPrime(512, random.randbytes), getPrime(512, random.randbytes)
n = p*q
phi = (p-1)*(q-1)

assert n == origin_N
d = pow(e, -1 , phi)

assert d * e % phi == 1


C = bytes_to_long(open('flag.enc', 'rb').read())
flag = long_to_bytes(pow(C, d, n))
print(flag)
```

### bit by bit

#### 加密

把明文的每16個字元分成一個chunk  
有一把key, 一個個iv  
每次對一個chunk，用`key + iv`進行xor加密  
每次結束後，`iv = (iv + 1) % 256`

#### 解法

![image](https://hackmd.io/_uploads/ByIXyj70R.png)
用xortool可以先得到key的前15bytes

solve:
```python
from pwn import *
from Crypto.Util.number import *
import sys

blocksize = 16



def transmit():

    key = bytes_to_long(b'\x00\x00\x00\x00\xae\xcdK\x13\x90E#\xeai\xba\xfe\x00')

    iv = 0
    msg = open('cipher.txt', 'rb').read()
    chunks = [msg[i:i+16] for i in range(0,len(msg), 16)]

    send = b''
    for chunk in chunks:
        iv = (iv+1) % 255
        curr_k = b'\x00' * 4 + long_to_bytes(key+iv)
        plain = xor(curr_k, chunk)
        send += plain
    print(send.decode())
    sys.exit(0)

if __name__=="__main__":
    transmit()
```

### protected console

btw這題因為這邊連線速度太慢，主辦方幫忙代跑腳本  
![image](https://hackmd.io/_uploads/HJzAro7AR.png)


#### 加密

多次加密  
|||
|:-:|-|
|encryption|AES(CBC_MODE, 128bits)|
|data|`user_hex_input[16:]`| 
|iv|`user_hex_input[:16]`|

題目會解析密文(json)，並讀出`username`和`role`的值  
一旦`username` = `"administrative_user"`, `role` = `1`  
就可以進入admin console，可執行`print()`指令

#### 解法

---
弱點  
![image](https://hackmd.io/_uploads/ryv4Bo70R.png)  
解密後會判斷padding是否正常  
這讓我們可以用`padding oracle`來獲得block解密後的訊息  
再加上可控制iv，所以我們可以有辦法改變整個密文  


---
padding檢查:  
![image](https://hackmd.io/_uploads/BJf7Ijm0C.png)  
但這個padding判斷的方式有點奇怪  
如果只需一個bytes的padding，可以是`\x00`或`\x01`  
所以padding oracle要先找出最後一個byte是`\x00`和`\x01`
並判斷哪個是`\x01` (`\x00`倒數第二個byte必定找不到因為`\x02\x03`不符合padding規則)


我們知道  

\begin{aligned}
    P_1 &= D(C_1) \oplus IV \\
    P_2 &= D(C_2) \oplus C_1 \\
    P_3 &= D(C_3) \oplus C_2 \\
\end{aligned}

所以我們可以透過padding oracle構造這些資料

\begin{aligned}
    C_3 &= \text{aaaaaaaaaaaaaaaa} \\
    C_2 &= D(C_3) \oplus P_3 \\
    C_1 &= D(C_2) \oplus P_2\\
    IV &= D(C_1) \oplus P_1\\
\end{aligned}

送出$IV+C_1+C_2+C_3$就可以進入admin console了
最後利用bit flipping 執行`print(flag)`


## Reverse

### Packed Full Of Surprises

先說我好像是非預期解

#### 執行檔功能

可以讀入`flag.txt`  
加密後寫出`flag.txt.enc`  

#### 解法

我發現密文沒有做好diffusion，也就前後字元關連不大  
於是我把原本的`flag.txt.enc`存成`encrypted_flag.enc`
把file read/write 當做 input/out
solve:
```python
import subprocess
from tqdm import *


elf_path = "./encrypt" 



flag = b''

correctflag = open('encrypted_flag.enc', 'rb').read()

for i, ch in enumerate(correctflag):

    for byte in trange(0x20, 0x7f):
        open('flag.txt', 'wb').write(flag + bytes([byte]))
        subprocess.run([elf_path])
        result = open('flag.txt.enc', 'rb').read()
        if result[i] == ch:
            flag += bytes([byte])
            break
    print(flag)
```

### AI rnd

#### 執行檔功能

會把輸入雜湊後(?，輸出

#### 解法
也是一樣diffusion沒有做好，但相同字元可能會出現分歧，但我們可以猜測flag的字元
![image](https://hackmd.io/_uploads/HkWH0jQCA.png)

```python

import subprocess
from tqdm import *


elf_path = "./ai_rnd" 



flag = ''

cur = 'a5 39 24 90 a8 a5 88 77 26 e4 3c 14 03 1e ba 3c 7d bb dc d6 aa 90 50 c9 0f aa dd 57 33 e1 a4 c7'.split()
for i in range(64):
    a = []
    for byte in range(0x20, 0x7f):
        process = subprocess.Popen(
            [elf_path], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )

        
        stdout, stderr = process.communicate(input=flag + chr(byte))                    
        if stdout.split()[i] == cur[i]:
            print(flag)
            a.append(chr(byte))
    
    if len(a) > 1:
        print(a)
        i = input('what: ')
        flag += i
    else:
        flag += a[0]
```

