
## 1) PowerShell Base64 Encode & Decode
if you have access to terminal using a webshell you can 


- base64 a file that you want to transfer
```bash
cat shell| base64 -w 0 ; echo
YmFkIHRoaW5ncyBoYXBwZW4gaGVyZQo=


 md5sum shell
2eebc05b20651f70efb2d195bbdaf2c2  shell
```


- paste it in powershell
```powershell
[IO.File]::WriteAllBytes("C:\Users\kokom\Desktop\testing\shell",[Convert]::FromBase64String("YmFkIHRoaW5ncyBoYXBwZW4gaGVyZQo="))


Get-FileHash .\shell -Algorithm MD5

Algorithm       Hash                                                                   Path                                 
---------       ----                                                                   ----                                 
MD5             2EEBC05B20651F70EFB2D195BBDAF2C2  
```



**Note:** While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.
