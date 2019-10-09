# Neurosurgery - Coding/Forensics challenge

Original task description:
```
Neurosurgery
1000
Author: Sin__

Are you tired of reverse engineering tasks? Want some forward engineering for a change?

We have just the thing for you! Grab this screen recording and memory dump and go find out what the program would have printed by doing a neuro-transplant.

Remember: forward, not reverse! https://drive.google.com/open?id=1P870cl2o6jPyVLA2VoXPVnUMuhcgGQ9g
```

First of all, this task is placed in the Coding/Forensics category and not the Reverse Engineering category. This should prove very useful later on.

The archive provided has two files:
```shell
$ file *
2019-07-18 16-13-25.flv: Macromedia Flash Video
test.elf:                ELF 64-bit LSB core file x86-64, version 1 (SYSV)
```
One is a screen recording, playing it reveals the origin of the second file: a RAM dump.
Here are some key aspects of the recording:
- The OS is Ubuntu 19.04, kernel 5.0.0-20-generic x86_64
- First a process called `zeromem` is ran until it is called because it exhausts all memory. This process just zeroes out everything such that the final image is compressible to the max.
- Then another process exhausts another resource: it writes a `fill_disk` file full of zeroes
- Next, the main challenge binary called `neuro` is started. It will print:
```
Please wait while I compute the flag for ya!
Progress 0%
Progress 1%
Progress 2%
```
- Then, the process is suspended. The VM is also paused.
- The VM RAM is dumped using `vboxmanage debugvm ... dumpvmcore`
- Finally, a script called `mitigate_easy_solution.py` is applied to the RAM dump. Although this script is not given, its purpose is to ensure that the solver can't just simply carve the ELF from memory and run it from start.
- The file is hashed using SHA256 and given to the solver


## Solution
Taking into account the task text which hints this is not a reverse engineering task but a coding (forward engineering) one, what would be the end solution? Well, this is also given in the task text: `a neuro-transplant`. The process context must be extracted from the RAM dump and kickstarted into a new VM. The challenge tests your knowledge on Linux OS internals, basically.

To carve the process context we must first bridge the semantic gap between the Host and the Guest by creating a Volatility profile. This is documented in many online tutorials and will be skipped. It is just a matter of compiling a kernel module on top of the exact kernel that is running in the VM. We have this information mentioned in the first bullet point above.

Next, we can check that the profile works by using the `pslist command`:
```shell
$ vol.py --profile=LinuxUbuntu1904x64 -f ./test.elf linux_pslist
Offset             Name                 Pid             PPid            Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- --------------- ------ ------------------ ----------
0xffff911ebe714500 systemd              1               0               0               0      0x000000003df54000 0
........
0xffff911ebae52e00 snapd                687             1               0               0      0x000000003aef8000 0
0xffff911ebae51700 atd                  688             1               0               0      0x000000003aea4000 0
0xffff911eb8851700 gpm                  718             1               0               0      0x000000003a960000 0
0xffff911eb35d0000 login                720             1               0               1000   0x000000003a2ba000 0
0xffff911eb35d5c00 unattended-upgr      725             1               0               0      0x000000003a908000 0
0xffff911eb8884500 systemd              899             1               1000            1000   0x000000003879a000 0
0xffff911eb8880000 (sd-pam)             900             899             1000            1000   0x000000003a2ee000 0
0xffff911eb7cb0000 bash                 910             720             1000            1000   0x0000000038346000 0
0xffff911eb83b8000 sudo                 919             910             0               0      0x00000000383b0000 0
0xffff911eb83bc500 su                   920             919             0               0      0x00000000383b2000 0
0xffff911eb83bae00 bash                 921             920             0               0      0x0000000037d04000 0
0xffff911eb8391700 neuro                944             921             0               0      0x00000000385ba000 0

```
The neuro process has pid 944 and the task_struct at 0xffff911eb8391700. All good so far.

To get it working, the minimum we would need is to have the same memory mappings and register context before being suspended.

The memory mappings can be obtained quite easily:
```shell
$ vol.py --profile=LinuxUbuntu1904x64 -f ./test.elf linux_dump_map -p 944 -D dump_dir/
Volatility Foundation Volatility Framework 2.6.1
Task       VM Start           VM End                         Length Path
---------- ------------------ ------------------ ------------------ ----
       944 0x0000000008048000 0x0000000008049000             0x1000 dump_dir/task.944.0x8048000.vma
       944 0x0000000008049000 0x00000000081fa000           0x1b1000 dump_dir/task.944.0x8049000.vma
       944 0x00000000081fa000 0x00000000081fb000             0x1000 dump_dir/task.944.0x81fa000.vma
       944 0x00000000081fb000 0x0000000008806000           0x60b000 dump_dir/task.944.0x81fb000.vma
       944 0x0000000008806000 0x0000000008a06000           0x200000 dump_dir/task.944.0x8806000.vma
       944 0x000000000904f000 0x0000000009071000            0x22000 dump_dir/task.944.0x904f000.vma
       944 0x00000000f7cf1000 0x00000000f7dbb000            0xca000 dump_dir/task.944.0xf7cf1000.vma
       944 0x00000000f7dbb000 0x00000000f7dbc000             0x1000 dump_dir/task.944.0xf7dbb000.vma
       944 0x00000000f7dbc000 0x00000000f7dbd000             0x1000 dump_dir/task.944.0xf7dbc000.vma
       944 0x00000000f7dbd000 0x00000000f7f93000           0x1d6000 dump_dir/task.944.0xf7dbd000.vma
       944 0x00000000f7f93000 0x00000000f7f94000             0x1000 dump_dir/task.944.0xf7f93000.vma
       944 0x00000000f7f94000 0x00000000f7f96000             0x2000 dump_dir/task.944.0xf7f94000.vma
       944 0x00000000f7f96000 0x00000000f7f98000             0x2000 dump_dir/task.944.0xf7f96000.vma
       944 0x00000000f7f98000 0x00000000f7f9a000             0x2000 dump_dir/task.944.0xf7f98000.vma
       944 0x00000000f7fa3000 0x00000000f7fa5000             0x2000 dump_dir/task.944.0xf7fa3000.vma
       944 0x00000000f7fa5000 0x00000000f7fa8000             0x3000 dump_dir/task.944.0xf7fa5000.vma
       944 0x00000000f7fa8000 0x00000000f7fa9000             0x1000 dump_dir/task.944.0xf7fa8000.vma
       944 0x00000000f7fa9000 0x00000000f7fd0000            0x27000 dump_dir/task.944.0xf7fa9000.vma
       944 0x00000000f7fd1000 0x00000000f7fd2000             0x1000 dump_dir/task.944.0xf7fd1000.vma
       944 0x00000000f7fd2000 0x00000000f7fd3000             0x1000 dump_dir/task.944.0xf7fd2000.vma
       944 0x00000000ff908000 0x00000000ff929000            0x21000 dump_dir/task.944.0xff908000.vma
```

Note: Since all the addresses are 32 bit wide and because the first one is 0x08048000, we realize this is actually a 32-bit executable (running on a 64-bit system).

The register context should be easy to obtain either by trial-and-error (replicating with an artificial process and setting the register to known values, suspending and seeing where they lie) or by doing some archeology on the Linux kernel. I chose the first variant and ended up with 0x238 as the offset from the kernel stack. One of the challenge testers did the second method and came up with the same offset after some more work.

```
$ vol.py --profile=LinuxUbuntu1904x64 -f ./test.elf  linux_volshell
In [1]: ts = obj.Object('task_struct', 0xffff911eb8391700, vm = addrspace());
In [2]: dt('task_struct')
 'task_struct' (9152 bytes)
0x0   : thread_info                    ['thread_info']
0x10  : state                          ['long']
0x18  : stack                          ['pointer', ['void']]
....
0x12c0: thread                         ['thread_struct']

In [12]: dt('pt_regs', ts.thread.sp + 0x238)
[CType pt_regs] @ 0xFFFFB4C7019DFF58
0x0   : r15                            0
0x8   : r14                            0
0x10  : r13                            0
0x18  : r12                            0
0x20  : bp                             0
0x28  : bx                             4160561152
0x30  : r11                            642
0x38  : r10                            0
0x40  : r9                             0
0x48  : r8                             0
0x50  : ax                             142629648
0x58  : cx                             0
0x60  : dx                             0
0x68  : si                             4287789996
0x70  : di                             134513612
0x78  : orig_ax                        18446744073709551379
0x80  : ip                             134567693
0x88  : cs                             35
0x90  : flags                          534
0x98  : sp                             142229756
0xa0  : ss                             43
In [13]: hex(134567693) # eip
Out[13]: '0x805570d'
```
The eip checks out. Next we can create an ELF file that loads the mappings at the corresponding addressed and then sets the register context, with eip being the last one. Doing this will not work as there is more investigative work to be done.

By looking at the current eip, we are greeted with a horrorful image. It seems that the binary is obfuscated with the [movfuscator](https://github.com/xoreaxeaxeax/movfuscator).
```asm
gdb-peda$ x/20i 0x805570d
   0x805570d:	mov    eax,DWORD PTR [eax-0x200068]
   0x8055713:	mov    eax,DWORD PTR [eax-0x200068]
   0x8055719:	mov    eax,DWORD PTR [eax-0x200068]
   0x805571f:	mov    eax,DWORD PTR [eax-0x200068]
   0x8055725:	mov    eax,DWORD PTR [eax-0x200068]
   0x805572b:	mov    eax,DWORD PTR [eax-0x200068]
   0x8055731:	mov    eax,DWORD PTR [eax-0x200068]
   0x8055737:	mov    eax,DWORD PTR [eax-0x200068]
   0x805573d:	mov    eax,DWORD PTR [eax-0x200068]
   0x8055743:	mov    edx,DWORD PTR ds:0x8605c58
   0x8055749:	mov    ds:0x8605c74,eax
   0x805574e:	mov    eax,DWORD PTR [edx*4+0x8605c70]
   0x8055755:	mov    edx,DWORD PTR ds:0x825cb5c
   0x805575b:	mov    DWORD PTR [eax],edx
   0x805575d:	mov    eax,ds:0x825cb5c
   0x8055762:	mov    edx,DWORD PTR ds:0x825cb58
   0x8055768:	mov    ds:0x8405af0,eax
   0x805576d:	mov    DWORD PTR ds:0x8405af4,edx
   0x8055773:	mov    eax,0x0
   0x8055778:	mov    edx,0x0
```
By compiling the simplest Hello World program using the movfuscator, or by reading the associated paper, we learn that it employs signal handlers for control flow. Thus, we need to extract the signal handlers installed in the process as well.
```
In [35]: for sig in range(32): print sig+1, hex(ts.sighand.action[sig].sa.sa_handler)
1 0x0L
2 0x0L
3 0x0L
4 0x8048447L (SIGILL)
5 0x0L
6 0x0L
7 0x0L
8 0x0L
9 0x0L
10 0x0L
11 0x80483c0L (SIGSEGV)
12 0x0L
13 0x0L
14 0x0L
15 0x0L
16 0x0L
17 0x0L
18 0x0L
19 0x0L
20 0x0L
21 0x0L
22 0x0L
23 0x0L
24 0x0L
25 0x0L
26 0x0L
27 0x0L
28 0x0L
29 0x0L
30 0x0L
31 0x0L
32 0x0L

```
Installing these signal handlers is enough to kickstart the binary. Indeed, the binary *almost* works, as you can see in the following snippet.
```shell
$ ./sample_solve
Progress 3%
Progress 4%
Progress 5%
Progress 6%
Progress 7%
Progress 8%
...
Progress 99%
Progress 100%
PTBCTF{
```
It frustratingly gets stuck right when it should print the flag. This happens as there is one
last piece of context that we didn't take into consideration: the thread local storage in the gs segment.
Without it, syscalls issued using `call gs:0x10` will fail and so will other functions. By replicating the full process in a VM on an executable without movfuscator, the solver could easily see where the segmentation fault occurs. However, in a movfuscated binary, the segmentation fault is caught by the internal handler and loops indefinitely without a clear cause.


In the end, this is what a sample solution looks like; there are some redundancies as this is part of something automatically generated by another Python script.

```c
#include <asm/ldt.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

////////////////////  gcc -nostdlib -masm=intel sample.c  -o sample_solve -m32 -pie

void *Xsyscall(uint32_t nr, void *a1, void *a2, void *a3, void *a4, void *a5){
	__asm__ __volatile__("mov eax, %0"
				:
				:"g"(nr)
				: "eax" );
	__asm__ __volatile__("mov ebx, %0"
				:
				:"g"(a1)
				: "ebx" );
	__asm__ __volatile__("mov ecx, %0"
				:
				:"g"(a2)
				:"ecx" );
	__asm__ __volatile__("mov edx, %0"
				:
				:"g"(a3)
				: "edx" );

	__asm__ __volatile__("mov esi, %0"
				:
				:"g"(a4)
				:"esi" );

	__asm__ __volatile__("mov edi, %0"
				:
				:"g"(a5)
				:"edi" );

	__asm__ __volatile__("push ebp; mov ebp, 0; int 0x80; pop ebp");
}

int open (const char *__file, int __oflag, ...){
	return (int) Xsyscall(5, (void*)__file, (void*)__oflag, NULL, NULL, NULL);
}
int fstat(int fd, struct stat *buf){
	return (int) Xsyscall(197, (void*)fd, (void*)buf, NULL, NULL, NULL);
}

void * Xmmap(void *addr, size_t length, int prot, int flags,int fd) {
	return (void*)Xsyscall(192, (void*)addr, (void*)length, (void*)prot, (void*)flags, (void*)fd); //asume offset is 0
}
void exit(int status) {
	Xsyscall(1, (void*)status, NULL, NULL, NULL, NULL);
}
int close(int fd) {
	return (int)Xsyscall(6, (void*)fd, NULL, NULL, NULL, NULL);
}
int arch_prctl(int code, unsigned long addr){
	return (int)Xsyscall(172, (void*)code, (void*)addr, NULL, NULL, NULL);
}

int Xsigaction(int signum, unsigned long addr){
        return (int)Xsyscall(174, (void*)signum, (void*)addr, NULL, 8, NULL);
}

int set_thread_area(struct user_desc *u_info){
	return (int)Xsyscall(243, (void*)u_info, NULL, NULL, NULL, NULL);
}

void Xmemset(char *dst, char c, int sz){
	int i;
	for(i = 0 ; i < sz; i ++)
		dst[i] = c;
}

////////////////////


void load_at(char *file_path, void *load_address) {
   char buf[400];
   struct stat *sb = buf;


   int fd = open(file_path, O_RDONLY);
   fstat(fd, sb);
   void *ptr = Xmmap(load_address, sb->st_size,PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_FIXED, fd);

    if ( ptr == MAP_FAILED || ptr != load_address)
    {
     exit(-1);
    }

    close(fd);
}


void _start() {
	load_at("dump_dir/task.944.0x8048000.vma", (void*)0x8048000ULL);
	load_at("dump_dir/task.944.0x8049000.vma", (void*)0x8049000ULL);
	load_at("dump_dir/task.944.0x81fa000.vma", (void*)0x81fa000ULL);
	load_at("dump_dir/task.944.0x81fb000.vma", (void*)0x81fb000ULL);
	load_at("dump_dir/task.944.0x8806000.vma", (void*)0x8806000ULL);
	load_at("dump_dir/task.944.0x904f000.vma", (void*)0x904f000ULL);
	load_at("dump_dir/task.944.0xf7cf1000.vma", (void*)0xf7cf1000ULL);
	load_at("dump_dir/task.944.0xf7dbb000.vma", (void*)0xf7dbb000ULL);
	load_at("dump_dir/task.944.0xf7dbc000.vma", (void*)0xf7dbc000ULL);
	load_at("dump_dir/task.944.0xf7dbd000.vma", (void*)0xf7dbd000ULL);
	load_at("dump_dir/task.944.0xf7f93000.vma", (void*)0xf7f93000ULL);
	load_at("dump_dir/task.944.0xf7f94000.vma", (void*)0xf7f94000ULL);
	load_at("dump_dir/task.944.0xf7f96000.vma", (void*)0xf7f96000ULL);
	load_at("dump_dir/task.944.0xf7f98000.vma", (void*)0xf7f98000ULL);
	load_at("dump_dir/task.944.0xf7fa3000.vma", (void*)0xf7fa3000ULL);
	load_at("dump_dir/task.944.0xf7fa5000.vma", (void*)0xf7fa5000ULL);
	load_at("dump_dir/task.944.0xf7fa8000.vma", (void*)0xf7fa8000ULL);
	load_at("dump_dir/task.944.0xf7fa9000.vma", (void*)0xf7fa9000ULL);
	load_at("dump_dir/task.944.0xf7fd1000.vma", (void*)0xf7fd1000ULL);
	load_at("dump_dir/task.944.0xf7fd2000.vma", (void*)0xf7fd2000ULL);
	load_at("dump_dir/task.944.0xff908000.vma", (void*)0xff908000ULL);

	struct user_desc u;
	u.entry_number = -1;
	u.base_addr = 0xf7fa4500;
	u.limit = 1048575;
	u.seg_32bit = 1;
	u.contents = 0;
	u.read_exec_only = 0;
	u.limit_in_pages = 1;
	u.seg_not_present = 0;
	u.useable = 1;
	set_thread_area(&u);

	unsigned short seg = (u.entry_number *8) | 3;

	char buf[400] = {0};
  struct sigaction *act = &buf;

  act->sa_sigaction = 0x8048447;
	buf[7] = 0x40;
  Xsigaction(SIGILL, act);

  act->sa_sigaction = 0x80483c0;
	buf[7] = 0x40;
  Xsigaction(SIGSEGV, act);

  __asm__ __volatile__("mov gs, %0" : : "r"(seg) );
	__asm__ __volatile__("mov edi, 0x80483cc");
	__asm__ __volatile__("mov esi, 0xff927bac");
	__asm__ __volatile__("mov ecx, 0x0");
	__asm__ __volatile__("mov ebp, 0x0");
	__asm__ __volatile__("mov edx, 0x0");
	__asm__ __volatile__("mov ebx, 0xf7fd2000");
	__asm__ __volatile__("mov esp, 0x87a40fc");
	__asm__ __volatile__("mov eax, 0x8805b10");
	__asm__ __volatile__("push 0x805570d");
	__asm__ __volatile__("ret");

}

```
