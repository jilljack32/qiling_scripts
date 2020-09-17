from qiling import *
from itertools import cycle

# Address of our input string
input_address = 0x00402159

def check_input_chr(ql):
    f = open("log.txt", "r")
    data = int(f.read())
    f.close()
    
    # Check if there is change in edi address
    # this means that we have found the right char
    # 004010C9 | 66:0F45CA        | cmovne cx,dx                            |
    # 004010CD | 58               | pop eax                                 |
    # 004010CE | E3 07            | jecxz very_success.4010D7               |
    # 004010D0 | 83EF 02          | sub edi,2                   <-- we hook here
    # 004010D3 | E2 CD            | loop very_success.4010A2                |
    # 004010D5 | EB 02            | jmp very_success.4010D9                 |
    if (data > int(ql.reg.edi)):
        # Track value in EDI to find if our input is right
        # If the value in EDI changes during next iteration it means we have a right character
        f = open("log.txt", "w")
        f.write(str(ql.reg.edi))
        f.close()

        print(hex(data), hex(ql.reg.edi))
        gotcha_input = ql.mem.read(input_address, 40)
        
        print(gotcha_input)        
        
        # Read the offset and advance it to find the next valid char in the input
        offset = ql.mem.read((input_address)+0x100, 1)
        offset = int.from_bytes(offset, "big")
        offset += 1
        ql.mem.write((input_address)+0x100, int.to_bytes(offset, 1, "big"))
        
        # Save the memory containing valid input uptil now and the registry changes
        ql.mem.write(input_address, bytes(gotcha_input))
        ql.save(mem=True, reg=True, cpu_context=True, snapshot="/tmp/snapshot.bin")
        ql.emu_stop()

def setup_inp_len(ql):
    # This is length of the input - should be > 25
    ql.mem.write(ql.reg.ebp+0x10, b'\x27')
    
    # This is random hex blob that's used to calculate the flag
    ql.mem.write(ql.reg.ebp+0x8, b'\xE4\x10\x40\x00')

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)

    # Populate the memory with random input
    # This will evolve to our flag
    ql.mem.string(input_address, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    
    # Populate the length of the input here
    ql.hook_address(setup_inp_len, 0x00401093)

    # This will be used as index into our random input
    ql.mem.write(input_address+0x100, b'\x00')

    # Make a initial snapshot
    ql.save(mem=True, reg=True, cpu_context=True, snapshot="/tmp/snapshot.bin")

    printable_chars = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9','`','~','!','@','#','$','%','^','&','*','(',')','_','-','+','=','|',']','}','[','{',"'",'"',';',':','/','?','.','>',',','<','}',']']
    chr_cycle = cycle(printable_chars)

    # Hook at this address to check if our char input worked 
    ql.hook_address(check_input_chr, 0x004010D0)

    # This file will be used to track if we have found the 
    # right char in the input
    f = open("log.txt", "w")
    f.write('9999999')
    f.close()

    # Loop to replace the chars in input with the list of chars 
    # one offset the another after find the right char
    for i in range(2000):
        inp_char = next(chr_cycle)
        
        # Store the offset where we need to process
        # the char in the input. This will be advanced by 1
        # after we find the right char in the input
        offset = ql.mem.read(input_address+0x100, 1)        
        offset = int.from_bytes(offset, "big")

        # Get a char from the char list and see if it's right
        ql.mem.write(input_address + offset, bytes(inp_char, 'utf-8'))
        
        # Run the function that's responsible for evaluating the flag
        ql.run(begin=0x0040104C, end=0x004010DE)
        
        # Save and restore the snapshot as we find each of the right
        # char in the input
        ql.restore("/tmp/snapshot.bin")


if __name__ == "__main__":
    # execute Windows EXE under our rootfs
    my_sandbox(["rootfs/x86_windows/bin/very_success"], "rootfs/x86_windows")
