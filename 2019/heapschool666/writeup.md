# Heap School 666 - Memory Corruption challenge

Original task description:
```
Heap School 666
1000
Author: Sin__

All the heap bugs have allegedly been patched in libc 2.30 according to various sources (https://twitter.com/amaris_nx/status/1157219569343389696).
Well then, let's play with some older but easier stuff: libc 2.24

nc 52.142.217.130 13370
```

The concept of the task is based on a previous challenge that appeared in Tokyo Westerns CTF (Simple note 2) which gave you at most 8 allocations and a simple vulnerability.
This task reduces the number of allocations to just 2 and also adds seccomp to make it more interesting:
```bash
$ checksec ./HeapSchool666
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
All default protections are activated (including seccomp as mentioned before).

The binary is a classical menu challenge:
```c
void print_banner()
{
        puts("Welcome to the Heap School 666 Note Service. Available options: ");
        puts(" 1 - Add new note (maximum 2 notes)");
        puts(" 2 - Show one of the written notes");
        puts(" 3 - Free one of the written notes");
}
```
However, the free_note functionality is not actually callable.

### Vulnerability 1
```c
#define NOTE_COUNT 2
char* note_array[NOTE_COUNT];

void do_show_note() {
        puts("Which one do you want to see?");
        int32_t idx = get_number();
        if (note_array[idx] == 0) {
                puts("Empty note!");
        } else {
                puts("--------------------------");
                puts(note_array[idx]);
                puts("--------------------------");
        }
}
```
Although the buffer holds at most 2 notes, the user can check any index they like. Is there anything useful after the buffer? By entering a note and dumping the note array contents in gdb:
```gdb
gdb-peda$ telescope 0x000055bd9c772000+0x4050 100
0000| 0x55bd9c776050 --> 0x55bd9e315910
0008| 0x55bd9c776058 --> 0x0
0016| 0x55bd9c776060 --> 0x0
0024| 0x55bd9c776068 --> 0x0
0032| 0x55bd9c776070 --> 0x0
0040| 0x55bd9c776078 --> 0x0
0048| 0x55bd9c776080 --> 0x0
0056| 0x55bd9c776088 --> 0x0
0064| 0x55bd9c776090 --> 0x0
0072| 0x55bd9c776098 --> 0x0
0080| 0x55bd9c7760a0 --> 0x0
0088| 0x55bd9c7760a8 --> 0x0
0096| 0x55bd9c7760b0 --> 0x0
0104| 0x55bd9c7760b8 --> 0x0
0112| 0x55bd9c7760c0 --> 0x0
0120| 0x55bd9c7760c8 --> 0x0
0128| 0x55bd9c7760d0 --> 0x0
0136| 0x55bd9c7760d8 --> 0x0
0144| 0x55bd9c7760e0 --> 0x0
0152| 0x55bd9c7760e8 --> 0x0
0160| 0x55bd9c7760f0 --> 0x0
0168| 0x55bd9c7760f8 --> 0x0
```
After the note_array there are only zeroes until the memory map ends. However, before the note_array there are some interesting pointers:
```
0552| 0x55fdd4ac4f58 --> 0x7f51a8a16ce0 (<__GI___libc_free>:	push   r13)
0560| 0x55fdd4ac4f60 --> 0x7f51a8d79360 (<seccomp_init>:	push   rbx)
0568| 0x55fdd4ac4f68 --> 0x7f51a8a00920 (<_IO_puts>:	push   r13)
0576| 0x55fdd4ac4f70 --> 0x7f51a8d795c0 (<seccomp_load>:	push   rbx)
0584| 0x55fdd4ac4f78 --> 0x7f51a8d79a50 (<seccomp_rule_add_exact>:	sub    rsp,0xc8)
0592| 0x55fdd4ac4f80 --> 0x7f51a8aaaf20 (<__stack_chk_fail>:	lea    rdi,[rip+0x72644]        # 0x7f51a8b1d56b)
0600| 0x55fdd4ac4f88 --> 0x7f51a89e6510 (<__printf>:	sub    rsp,0xd8)
0608| 0x55fdd4ac4f90 --> 0x7f51a8d793d0 (<seccomp_release>:	jmp    0x7f51a8d7e240)
0616| 0x55fdd4ac4f98 --> 0x7f51a8a5d1e0 (<alarm>:	mov    eax,0x25)
0624| 0x55fdd4ac4fa0 --> 0x7f51a8a88880 (<read>:	cmp    DWORD PTR [rip+0x2cdeb9],0x0        # 0x7f51a8d56740 <__libc_multiple_threads>)
0632| 0x55fdd4ac4fa8 --> 0x7f51a8a17550 (<__libc_calloc>:	mov    rdx,rdi)
0640| 0x55fdd4ac4fb0 --> 0x7f51a8a07a10 (<getchar>:	push   rbx)
0648| 0x55fdd4ac4fb8 --> 0x7f51a8a16930 (<__GI___libc_malloc>:	push   rbp)
0656| 0x55fdd4ac4fc0 --> 0x7f51a8a01230 (<__GI__IO_setvbuf>:	push   r13)
0664| 0x55fdd4ac4fc8 --> 0x7f51a89fc470 (<__isoc99_scanf>:	push   rbx)
0672| 0x55fdd4ac4fd0 --> 0x7f51a89ca2b0 (<__GI_exit>:	lea    rsi,[rip+0x387321]        # 0x7f51a8d515d8 <__exit_funcs>)
0680| 0x55fdd4ac4fd8 --> 0x0
0688| 0x55fdd4ac4fe0 --> 0x7f51a89b0300 (<__libc_start_main>:	push   r14)
0696| 0x55fdd4ac4fe8 --> 0x0
0704| 0x55fdd4ac4ff0 --> 0x0
0712| 0x55fdd4ac4ff8 --> 0x7f51a89ca550 (<__cxa_finalize>:	push   r15)
0720| 0x55fdd4ac5000 --> 0x0
0728| 0x55fdd4ac5008 (0x000055fdd4ac5008)
0736| 0x55fdd4ac5010 --> 0x0
0744| 0x55fdd4ac5018 --> 0x0
0752| 0x55fdd4ac5020 --> 0x7f51a8d52600 --> 0xfbad2887
0760| 0x55fdd4ac5028 --> 0x0
0768| 0x55fdd4ac5030 --> 0x7f51a8d518c0 --> 0xfbad208b
0776| 0x55fdd4ac5038 --> 0x0
0784| 0x55fdd4ac5040 --> 0x7f51a8d52520 --> 0xfbad2087
0792| 0x55fdd4ac5048 --> 0x0
```
Although it looks promising, only one pointer can actually be used because of the dereferencing: the self-referencing pointer. Using it, we obtain a PIE leak. Moreover, we do not use up any allocations.

Next, the key observation is that in most cases we can "jump" from the note_array to the heap as the mappings are usually very close. Some example runs:

```
0x000055fdd4ac6000 0x000055fdd4ac9000 rw-p	./hs666
0x000055fdd4cc3000 0x000055fdd4ce4000 rw-p	[heap]
Difference: (0x000055fdd4cc3000-0x000055fdd4ac9000)/8 = 0x3f400

0x0000558d3ddf8000 0x0000558d3ddfb000 rw-p	./hs666
0x0000558d3dfdc000 0x0000558d3dffd000 rw-p	[heap]
Difference: (0x0000558d3dfdc000-0x0000558d3ddfb000)/8 = 0x3c200

0x000055900eb74000 0x000055900eb77000 rw-p	./hs666
0x000055901030a000 0x000055901032b000 rw-p	[heap]
Difference:  (0x000055901030a000-0x000055900eb77000)/8 = 0x2f2600
```
This is well within the 32 bit value we can use as index. Also note that "precise landing" is not necessary. It suffices to not get a segmentation fault on the first jump and then we can just go back one memory page at a time until the target is reached. This drastically reduces the brute force attempts necessary. But... what exactly is the target? If we can force there to be a known value somewhere we also get the heap address for free. We then need the libc and we're done with ASLR!

### Vulnerability 2

```c
void do_read(char *buf, uint32_t sz) {
        int retcode = read(0, buf, sz - 1);
        if (retcode < 0){
                puts("No tricks please");
                exit(1);
        }
}

void do_add_note(int idx) {
        puts("How big?");
        int size = get_number();
        char* ptr = malloc(size);
        if (ptr == 0)
                exit(0);
        puts("Go:");
        do_read(ptr, size);
}
```

By adding a note with 0 length we can overflow however much we can get the read call to process in one go. Obviously, this leads to heap metadata corruption.

To obtain a libc pointer there are two methods, both implying the classical top chunk shrinking and then sending to the unsorted bin.
- the intended solution is to generate a pointer to a libc pointer on the heap
- the other solution found during QA testing is to insert a GOT pointer on the heap in the first allocation and then leak the libc by reading it.


### Scanf trick

An aspect not mentioned so far is that it would seem we do not have enough allocations to carry this out. Indeed, relying on the two explicit allocations is not enough. However, implicit allocations can be generated by abusing the scanf function.

If we feed a long string of zeroes to a `scanf("%d", ...)` call, a malloc and then multiple calls to realloc will be issued. This is useful to move the chunks from one bin to another.


### Summary

These are the major steps needed for the exploit:
- obtain the PIE leak
- try a "jump" into the heap. if the connection closes just try again as it has a high chance of succeeding (1 in 128 on average)
- use the first allocation to: overwrite the top chunk metadata to shrink it under one page
- use scanf to push the top chunk into the unsorted bin and create a new top chunk
- use scanf **again** to move the chunk from the unsorted bin to the large bin, thus creating the needed libc pointer on the heap
- read the libc pointer from the heap
- execute a House of Orange type attack

The missing piece is bypassing the vtable check in the 2.24 libc version and seccomp. This has been documented in other CTF challenges, the solution is to use another vtable from a string and then use the getcontext gadget in libc.
