Easy leaks

---
we have a `cat.ab` file.
```bash
$ file cat.ab
cat.ab: Android Backup, version 5, Compressed, Not-Encrypted
```
a bit of research suggests that this file is an android backup file created by `adb backup` command.
```bash
$ head -n 7 cat.ab
ANDROID BACKUP
5
1
none
xn6
   s$%
      "EH[$ݞOҡCac(vOXTYSϟ~#AuqG_i=!g^=7rAƭڋD˲UgFQ)˵13s6݄]yS
                                                          ܱ`M.ۼyӯlllLLbV6m(n֯|k)-ct6inoz_yټzLT_\
Oٓ[ؔ."[UD=5M0w1ܵVӊe:ɽ(gH0s bne;~aEX}St*'kJ'ϰ5za4'g(\Lֵ3m-WV
                                                       [+DGuz㋉8WLjŜ s.$df`q]q;aif;OFW
|:@p[18]gegͥ؟꣹
```
To open the file, we need to replace the first five bytes with proper gzip header.
```bash
$ (printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 cat.ab) | tar xfvz -
```
the flag will be present in an image at `shared/0/Pictures/IMAG0004.jpg`.