---
title: IrisCTF 2025
date: 2025-01-06
---

![alt text](image.png)
總排名`40/1529`|`TOP 2%`  

### solves (personal)

有些跟隊員有重複，但還是紀錄一下

|Category|solves|
|:--:|:--:|
|Reverse|1/6|
|Networks|1/4|
|Cryptography|1/4|
|Binary Exploitation|1/3|

## Reverse

### Crispy Kelp

這題是golang逆向，老實說我完全不懂golang，但不至於那麼難

#### main

![alt text](image-1.png)
可以搜尋main，找到他

首先觀察主程式`main_main`  
可以看到`os_Stdout`、`fmt_Fprint()`  
這代表他把`v29`寫出到標準輸出，也就是輸出函數  

然後看到`os_Stdout`、`fmt_Fscanln()`  
這代表他把`v29`寫入到標準輸入，也就是輸入函數  
![alt text](image-5.png)  
那麼從這裡可以看到他是`輸出`->`輸入`->`輸出`->`輸入`  
可以推測他跟main函數  
![alt text](image-3.png)

接下來進到最主要的`encodingString`  
`*p_string_0`是剛剛第二個input，`*p_int_0`是剛剛一個input


![alt text](image-21.png)

#### encodingString

  
首先會先生成金鑰  
![alt text](image-9.png)

透過gdb和decompiler的交互觀察
可以發現他是一個4bytes為單位的陣列，長度會跟`s`(剛剛傳進來的字串)一樣長，然後裡面會有隨機的byte
![alt text](image-11.png)
![alt text](image-14.png)
![alt text](image-12.png)
![alt text](image-10.png)

有了key之後就可以來逆加密方式了

1. s[0] ~ s[len - 1]是 `kelpa(剛剛傳入的數字) + (k[i] ^ s[i])`
![alt text](image-16.png)
2. s[len + 1] ~ s[2*len] 是 `kelpa + (kelpa(剛剛傳入的數字) + (k[i] ^ s[i])) ^ s[i]`
![alt text](image-17.png)  
3. s[len]是`kelpa`
![alt text](image-18.png)  
4. 把每個字元utf8 encode
![alt text](image-19.png)
5. hex encode
![alt text](image-20.png)

#### solve

```python
from pwn import *

buf = open('kelpfile_flag').read()
buf = bytes.fromhex(buf)
buf = buf.decode('utf-8')
buf = [ord(x) for x in buf]

slen = len(buf) // 2
xor1 = buf[:slen]
kelp = buf[slen]
xor2 = buf[slen + 1 :]


xor2 = [x - kelp for x in xor2]
key = [x ^ y for x, y in zip(xor1, xor2)]
plain = [(x - kelp) ^ y for x, y in zip(xor1, key)]
print(bytes(plain))
```