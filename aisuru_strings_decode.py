import sys
sys.path.append("..")
from qiling import *

def readString(ql, addr):
    res = ""
    length = 0
    while True:
        # read one byte at a time
        c = ql.mem.read(addr, 1).decode()

        if c == '\x00':
            break
        length += 1
        res += c
        addr += 1
    return res, length

def my_sandbox(path, rootfs):
    f = open("decrypted.txt", "w", encoding="utf-8")

    # The string table starts here
    reg_eax = 0x080525A0

    # Blindly try and decode 500 strings, don't care if it fails in between
    # For some unknown bug or my limited knowledge on qiling cannot rerun partial code without re-initializing qiling
    for i in range(500):
        ql = Qiling(path, rootfs)  
        print(f"EIP: {ql.reg.eip}")
        ql.reg.eax = reg_eax
        enc_res, enc_length = readString(ql, ql.reg.eax)      
        ql.run(begin=0x080482A0, end=0x08048355)
        res, length = readString(ql, ql.reg.edx)
        reg_eax += length + 1
        f.write(f"{enc_res} ---> {res}\n")

    f.close()

if __name__ == "__main__":
    my_sandbox(["rootfs/x86_linux/bin/aisuru_bot"], "rootfs/x86_linux")
