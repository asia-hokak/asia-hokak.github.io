---
title: CGGC 2024 初賽
date: 2024-11-10
---
## Intro
    
## Reverse

### lazy7

題目有一個壓縮資料的function  
![image](https://hackmd.io/_uploads/HyRywfc-1l.png)  
和一個把資料轉成16進位的function  
![image](https://hackmd.io/_uploads/S1nDwG9WJl.png)  

題目大概會這樣使用這些function  

題目檔案大概會做這件事  
壓縮->hex encode->壓縮->hex encode  

但仔細觀察你會發現他有把解壓縮和hex decode的function寫在檔案裡面  
所以只要做這件事就好了  
hex decode->解壓縮->hex decode->解壓縮  

```c
#include "defs.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>



_BYTE sub_140C(long long a1, int a2, long long a3)
{
  long long v3; // rdx
  int v4; // eax
  _BYTE *result; // rax
  int v7; // [rsp+20h] [rbp-18h]
  int i; // [rsp+24h] [rbp-14h]
  int j; // [rsp+28h] [rbp-10h]
  long long v10; // [rsp+2Ch] [rbp-Ch]
  int v11; // [rsp+34h] [rbp-4h]

  v7 = 0;
  for ( i = 0; i < a2; ++i )
  {
    v3 = 12LL * i;
    v10 = *(_QWORD *)(v3 + a1);
    v11 = *(_DWORD *)(v3 + a1 + 8);
    for ( j = 0; j < SHIDWORD(v10); ++j )
    {
      *(_BYTE *)(v7 + a3) = *(_BYTE *)(v7 - (int)v10 + a3);
      ++v7;
    }
    v4 = v7++;
    *(_BYTE *)(a3 + v4) = v11;
  }
  result = (_BYTE *)(v7 + a3);
  *result = 0;
  return result;
}

long long sub_1642(const char *a1, void **a2)
{
  int v3; // [rsp+14h] [rbp-1Ch] BYREF
  int v4; // [rsp+18h] [rbp-18h] BYREF
  int v5; // [rsp+1Ch] [rbp-14h] BYREF
  int i; // [rsp+20h] [rbp-10h]
  unsigned int v7; // [rsp+24h] [rbp-Ch]
  unsigned long long v8; // [rsp+28h] [rbp-8h]

  v7 = strlen(a1) / 0xA;
  *a2 = malloc(12LL * (int)v7);
  for ( i = 0; i < (int)v7; ++i )
  {
    sscanf(&a1[10 * i], "%4X%4X%2X", &v3, &v4, &v5);
    *((_DWORD *)*a2 + 3 * i) = v3;
    *((_DWORD *)*a2 + 3 * i + 1) = v4;
    *((_BYTE *)*a2 + 12 * i + 8) = v5;
  }
  return v7;
}

int main()
{
    void *comp2;
    void *comp1;
    char *de1;
    char *de2;
    long long len;

    len = sub_1642(output, &comp2);
    de1 = (char *)malloc(0x100000);
    sub_140C((long long)comp2, len, (long long)de1);

    const char *output = "000000003000010007360000000039000A000835000B00013000150007340000000032000A000946001E00093200320008370001000130003D00073300450008300032000142003C000937005A0009370064000946005A0009310078000331003B0004340000000045007800093300820009350096000938008C000935006900073"...(略)

    len = sub_1642(de1, &comp1);
    de2 = (char *)malloc(0x100000);
    sub_140C((long long)comp1, len, (long long)de2);
    
    printf("result: %s\n", de2);

    FILE *fp = fopen("flag", "wb");  // 開啟文件以寫入二進制模式
    fwrite(de2, 1, strlen(de2), fp);  // 寫入數據
    fclose(fp);


    free(comp2);
    free(de1);
    free(de2);

    return 0;

}

```

![image](https://hackmd.io/_uploads/Hk855zq-1g.png)  
把拿到的東西拿去base64decode就可以得到flag.png了:D  

### UnityFlagChecker

可以先把GameAssembly.dll用il2cppdumper彈出原本的資訊  
![image](https://hackmd.io/_uploads/HJr_jM9Z1e.png)  
這邊有一個checkstring，是加密後的flag，然後被base64 encode後  
![image](https://hackmd.io/_uploads/ryfhsz9-1e.png)  
這邊有一堆function，雖然不能看到裡面的內容，但可以看到他的VA  
![image](https://hackmd.io/_uploads/r1SohGq-ke.png)  


用ida開啟原本的GameAssembly.dll，然後分析裡面的東西，可以發現他是使用chacha20  

最後用x64 dbg在這個function設breakpoint，這會使他再加密前停止
![image](https://hackmd.io/_uploads/Hki7pGqW1x.png)

停在這裡
![image](https://hackmd.io/_uploads/BJ66Nm5Wye.png)
這邊r8是存要加密的資料的指標，選擇跟進後可以看到他的memory
![image](https://hackmd.io/_uploads/H1Ugrm5Zke.png)
接著把這段改成加密後的flag(base64decoded)
![image](https://hackmd.io/_uploads/H1KVBmqbyg.png)
r9改成flag的長度(0x36)
![image](https://hackmd.io/_uploads/BkWjHQ9Wyl.png)
然後continue，flag就會出來了
![image](https://hackmd.io/_uploads/rJxZIX5-Jl.png)
