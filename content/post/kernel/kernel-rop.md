+++
date = '2025-12-10T19:11:20+08:00'
draft = true
title = 'Kernel Rop'
+++

这里主要讲是内核的rop，也就是基础栈上的一个溢出漏洞这里我们进行一个原理的介绍

## 2018 强网杯 - core

这里我们先看一个ko文件和sh文件

**ko文件**，即**kernel object文件**，是Linux系统中用于加载驱动模块的文件。在Linux中，内核模块通常以.o文件存在，即object文件。而ko文件则专指内核模块加载文件，用于在需要时将驱动模块动态加载到内核中。

```bash
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko

poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f

```

```c
__int64 __fastcall core_ioctl(__int64 a1, int a2, __int64 a3)
{
  switch ( a2 )
  {
    case 0x6677889B:
      core_read(a3);
      break;
    case 0x6677889C:
      printk("\x016core: %d\n", a3);
      off = a3;
      break;
    case 0x6677889A:
      printk("\x016core: called core_copy\n");
      core_copy_func(a3);
      break;
  }
  return 0;
}

void __fastcall core_read(__int64 a1)
{
  char *v2; // rdi
  __int64 i; // rcx
  char v4[64]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+40h] [rbp-10h]

  v5 = __readgsqword(0x28u);
  printk("\x016core: called core_read\n");
  printk("\x016%d %p\n", off, (const void *)a1);
  v2 = v4;
  for ( i = 16; i; --i )
  {
    *(_DWORD *)v2 = 0;
    v2 += 4;
  }
  strcpy(v4, "Welcome to the QWB CTF challenge.\n");
  if ( copy_to_user(a1, &v4[off], 64) )
    __asm { swapgs }
}

void __fastcall core_copy_func(signed __int64 a1)
{
  _BYTE v1[64]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v2; // [rsp+40h] [rbp-10h]

  v2 = __readgsqword(0x28u);
  printk("\x016core: called core_writen");
  if ( a1 > 0x3F )
    printk("\x016Detect Overflow");
  else
    qmemcpy(v1, name, (unsigned __int16)a1);    // overflow
}

__int64 init_module()
{
  core_proc = proc_create("core", 438, 0, &core_fops);
  printk("\x016core: created /proc/core entry\n");
  return 0;
}
```

这里就是一个主要的代码了
