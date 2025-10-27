### challenge
Customers of secure-startup.com have been recieving some very convincing phishing emails, can you figure out why?

---
Flag #1
```bash
❯ dig secure-startup.com TXT +short
"v=spf1 a mx ?all - HTB{RIP_SPF_Always_2nd"
```
Flag #2
```bash
❯ dig _dmarc.secure-startup.com TXT +short
"v=DMARC1;p=none;_F1ddl3_2_DMARC}"
```