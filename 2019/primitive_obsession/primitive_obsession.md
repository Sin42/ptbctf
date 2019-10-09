# Primitive Obsession

This challenge is a bit of a tongue-in-cheek dedication to **Sin__**, who has pestered me countless times about defining structures in IDA to make analysis much easier and code much more readable (well, he's right, but only 99% of the time :D).

## Static analysis

We're asked to provide a series of credentials, security questions and answers, which are then passed through a multitude of checks that match various parts of the input disregarding type and force casting them to `float`/`int` and so on (which is why casting to struct makes things worse in this case).

Each "check" function returns 1 or 0, depending on whether the check is passed or not. A global "OK" state is kept between calls and logical AND is applied between it and each result. If at the end this OK is still 1, then all checks have passed and the input is valid.

One way to do it is to export the decompiler output and parse into expressions to feed to `claripy` (`z3` doesn't handle floating point well, as far as I'm aware). One team did use `z3` and figured out the floating point checks through trial and error and a bit of bruteforce.

## Symbolic execution

Side note: this challenge wasn't actually intended to be solved using [angr](https://angr.io/) or some other symbolic execution framework, since floating point has always been a bit tricky to work with for them - but it's a nice surprise to see it actually work (as seen in another writeup). I didn't manage to coax it into solving it under the time constraints (30 minutes), but I'm no good at optimizing solvers. YMMV.

**NOTE**: Manticore doesn't implement `fxsave` and `fxrstor` yet, so the following won't work until [this issue](https://github.com/trailofbits/manticore/issues/1489) is fixed. This is one of the reasons I didn't think it would be solvable with this approach.

Running it "raw" would take quite some time, but adding a few constraints can go a long way. One thing to do is to mention that all bytes are ASCII. The other thing is to reduce exploration time by specifying addresses which to avoid (and stop exploring states that go through those addresses). Each check function sets the return value using `mov eax, 0`.

```python
# Used in Binary Ninja
BIG_FUNCTION = bv.get_functions_at(0x4036fc)[0]
start_of_checks = 0x4039d3
end_of_checks = 0x404a1f

inst = list(BIG_FUNCTION.mlil.instructions)
targets = []
for i in inst:
    if i.operation == MediumLevelILOperation.MLIL_CALL and i.address >= start_of_checks and i.address <= end_of_checks:
        targets.append(i.operands[1].value.value)

print("[+] Collected {} function addresses".format(len(targets)))

avoid = []
for func_address in targets:
    func = bv.get_functions_at(func_address)[0]
    all_inst = list(func.instructions)
    for i in all_inst:
        if i[0][0].text == 'mov' and i[0][2].text == 'eax' and i[0][4].text == '0x0':
            avoid.append(i[1])

print("[+] Avoid: {}".format(list(map(hex,avoid))))
```

```python
from manticore.native import Manticore
from manticore.core.smtlib import operators

m = Manticore("./primitive_obsession")

# Gathered from BN
avoid = [0x4008be, 0x40090b, 0x400975, 0x4009df, 0x400a30, 0x400aa0, 0x400ae7, 0x400b38, 0x400b89, 0x400bd8, 0x400c28, 0x400c73, 0x400cc3, 0x400d2d, 0x400d8e, 0x400dde, 0x400e48, 0x400e94, 0x400efe, 0x400f68, 0x400fb9, 0x401005, 0x401056, 0x4010a7, 0x4010f9, 0x40114b, 0x40119c, 0x4011ec, 0x401237, 0x401286, 0x4012d0, 0x40131f, 0x401370, 0x4013c0, 0x401412, 0x401463, 0x4014b2, 0x401503, 0x401553, 0x4015a5, 0x4015eb, 0x40164c, 0x40169d, 0x4016ec, 0x40173c, 0x401788, 0x4017d8, 0x401829, 0x40187a, 0x4018ca, 0x401934, 0x401985, 0x4019d9, 0x401a2a, 0x401a76, 0x401ac7, 0x401b19, 0x401b68, 0x401bc0, 0x401c16, 0x401c66, 0x401cbc, 0x401d17, 0x401d77, 0x401dc8, 0x401e1f, 0x401e7a, 0x401ed5, 0x401f2b, 0x401f80, 0x401fdb, 0x402037, 0x402093, 0x4020ee, 0x40214b, 0x4021a6, 0x402203, 0x402258, 0x4022b5, 0x402310, 0x40236c, 0x4023c7, 0x402424, 0x40247f, 0x4024db, 0x402539, 0x402596, 0x4025ee, 0x40264a, 0x4026a5, 0x402702, 0x402754, 0x4027af, 0x402807, 0x402864, 0x4028da, 0x402935, 0x402995, 0x4029f5, 0x402a49, 0x402aa1, 0x402afc, 0x402b59, 0x402bad, 0x402c05, 0x402c7b, 0x402cd7, 0x402d34, 0x402d91, 0x402dee, 0x402e4a, 0x402ea7, 0x402f04, 0x402f60, 0x402fb8, 0x403013, 0x40306e, 0x4030ca, 0x403140, 0x40319d, 0x4031fa, 0x403257, 0x4032b2, 0x40330d, 0x403368, 0x4033c3, 0x40341b, 0x403470, 0x4034cd, 0x403529, 0x403584, 0x4035e0, 0x40363d, 0x40369d, 0x4036f5]

VERBOSE = True
before_read_addr = 0x403851
after_read_addr = 0x4039bf
sol_ok = 0x404a21

def set_hook_abandon(addr):
    @m.hook(addr)
    def abandon(state):
        if VERBOSE:
            print("Abandoning state at {:#x}".format(addr))
        state.abandon()

def main():
    m.context["solved"] = False
    max_length = 0x104
    m.verbosity(1)

    for addr in avoid:
        set_hook_abandon(addr)
    
    @m.hook(before_read_addr)
    def sym_inp(state):
        # Skip calls to read
        state.cpu.RIP = after_read_addr
        with m.locked_context() as context:
            solution = state.new_symbolic_buffer(max_length)

            # Constrain to printables
            for i in range(max_length):
                state.constrain(operators.AND(0x20 <= solution[i], solution[i] <= 126))
            
            credentials_address = state.cpu.RBP - 0x130
            context["input_address"] = credentials_address
            print("[+] input_address: {:#x}".format(credentials_address))
            state.cpu.write_bytes(credentials_address, solution)
    
    @m.hook(sol_ok)
    def party_time(state):
        with m.locked_context() as context:
            print("[+] found credentials")
            credentials_address = context["input_address"]
            flag = "".join(list(map(chr, state.solve_buffer(credentials_address, max_length))))
            print("[+] flag: {}".format(flag))
            context["solved"] = True
            m.kill()
    
    m.run()

if __name__ == "__main__":
    main()
```