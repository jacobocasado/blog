# What is ASLR
Due to the invention of ROP, operating system developers introduced Address Space Layout Randomization (ASLR) as an additional mitigation technique.
The goal of ASLR was to mitigate exploits that defeat DEP with ROP.
At a high level, ASLR defeats ROP by randomizing an EXE or DLL’s loaded address each time the application starts.  This way, gadgets cannot be used as the memory address of the gadget won't be the same each time the module is loaded.

To fully describe how Windows implements ASLR, we must briefly discuss basic executable file compilation theory.

When compiling an executable, the compiler accepts a parameter called the **preferred base address (for example 0x10000000)**, which sets the base memory address of the executable when it is loaded.
We should also take note of a related compiler flag called /REBASE, which if supplied, allows the loading process to use a different loading address. This flag is relevant if two DLLs were compiled with the same preferred base address and loaded into the same process.
If, as in our example, the first module uses 0x10000000, the operating system will provide an alternative base address for the second module. This is not a security mechanism, but merely a feature to avoid address collision.
To enable ASLR, a second compiler flag, /DYNAMICBASE must be set. This is set by default in modern versions of Visual Studio, but may not be set in other IDEs or compilers.

Within Windows, ASLR is implemented in two phases. 
First, when the operating system starts, the n**ative DLLs for basic SYSTEM processes load to randomized base addresses**.**The addresses selected for these native modules are not changed until the operating system restarts.** Windows will automatically avoid collisions by rebasing modules as needed. 

There are two things against ASLR that we must know to perform our attacks:
Next, when an application is started, any ASLR-enabled EXE and DLLs that are used are allocated to random addresses. If this includes a DLL loaded at boot as part of a SYSTEM process, its existing address is reused within this new application. We must take this into account for our attacks.
It is important to note that ASLR’s randomization does not affect all the bits of the memory base address. Instead, **only 8 of the 32 bits** are randomized when a base address is chosen. In technical terms, this is known as the amount of entropy applied to the memory address. The higher 8 bits and the lower 16 bits always remain static when an executable loads. We will also take this into account for our attacks against ASLR. 

Note that, on 64-bit versions of the Windows and Linux OS, ASLR has a larger entropy (up to 19 bits) and is therefore considered to be more effective.

# ASLR bypass theory
There are **four main techniques to bypass ASLR:**
- Exploit modules that are used and are not compiled with ASLR (remember this protection is per module):
	- If an EXE or DLL is compiled without ASLR support, **its image will be loaded to its preferred base address**, provided that there are no collision issues.
	- This means that, in these cases, we can locate gadgets for our ROP chain in an unprotected module and leverage that module to bypass DEP.
	- We can easily determine whether a module is compiled with ASLR by searching for the /DYNAMICBASE bit inside the DllCharacteristics field of the PE header.
- Exploit the low entropy of ASLR (only in 32 bits). 
	- Since the lower 16 bits of a memory address are non-randomized, we may be able to perform a partial overwrite of a return address.
	- We can only overwrite the last 2 bytes of the return address, which is very limited. Also, we are limited to that single gadget, meaning that our buffer overflow would halt inmediately after executing it (or use ROP gadgets if DEP is enabled).
- Brute force a base address:
	- This is possible on 32-bit because ASLR provides only 8 bits of entropy. 
	- The main limitation is that this only works for target applications that don’t crash when encountering an invalid ROP gadget address or in cases in which the application is automatically restarted after the crash.
	- If the application does not crash, we can brute force the base address of a target module in (at most) 256 attempts. If the application is restarted, it may take more attempts to succeed, but the attack is still feasible.
	- As an example, let’s consider a stack buffer overflow in a web server application. Imagine that every time we submit a request, a new child process is created. If we send our exploit and guess the ROP gadget’s base address incorrectly, the child process crashes, but the main web server does not. This means we can submit further requests until we guess correctly.
- Leak the base address of a loaded module, or the address of a function inside the module. **This is the more realistic and used in modern exploits.**
	- This technique leverages one or more vulnerabilities in the application in order to leak the address of a loaded module or function inside the module.
	- This leak is often created by exploiting a separate vulnerability, like a logic bug, that discloses memory or information, but does not allow code execution. A common info leak vulnerability type are the "format string" vulnerabilities.
	- Once we leak a module's address we can leverage another vulnerability as a stack overflow with ROP to bypass DEP (that will be most of the time also enabled, next to ASLR).
# ASLR and WDEG
Windows Defender Exploit Guard allows enabling ASLR and DEP to binaries that don't enforce it.
However, when forcing ASLR with WDEG, it is not applied to the main executable, only the loaded modules.

```
0:077> lm
start    end        module name
001b0000 001e3000   snclientapi   (deferred)             
00400000 00c0c000   FastBackServer   (deferred)             
00ce0000 00d0d000   libcclog   (deferred)             
01260000 0128b000   gsk8iccs   (deferred)             
01450000 01492000   NLS        (deferred)             
014b0000 014ea000   icclib019   (deferred)             
02ed0000 02fc0000   libeay32IBM019   (deferred)             
10000000 1003d000   SNFS       (deferred)             
50200000 50237000   CSNCDAV6   (deferred)             
50500000 50577000   CSFTPAV6   (deferred)             
51000000 51032000   CSMTPAV6   (deferred)             
```

The addresses for CSNCDAV6, CSFTPAV6 and CSMTPAV6, which are loaded modules, are always the same. 
But if we configure mandatory ASLR for this executable through WDEG we can see that these address change:

```
0:000> lm
start    end        module name
001a0000 001cd000   libcclog   (deferred)             
00400000 00c0c000   FastBackServer   (deferred)             
00c10000 00c4d000   SNFS       (deferred)             
00c50000 00c87000   CSNCDAV6   (deferred)             
01180000 011f7000   CSFTPAV6   (deferred)             
01200000 01233000   snclientapi   (deferred)             
01240000 01272000   CSMTPAV6   (deferred)             
6c2b0000 6c54b000   msi        (deferred)             
6c590000 6c65e000   CLUSAPI    (deferred)             
6c660000 6c80b000   dbghelp    (deferred)             
```

However, in this ASLR series we won't use the base module for the ASLR bypass, and we will try another type of ASLR bypass.
Also, the base module has null bytes at the start, which are badchars for our exploit.

# Info leak based ASLR
We will try to leak the base address of any of the modules.
This is normally done by exploiting a logical vulnerability or through memory corruption.

Our approach here will be to exploit a logical vulnerability in the application.
**Note: We could also find useful information more quickly by exploring the Win32 APIs imported by the application. If an imported API function could leak an info leak and such function is likely being used somewhere in the application, we may be able to exploit it. Most Win32 APIs do not possess a security risk but SOME OF THEM can be exploited to generate an info leak. Some of them include the DebugHelp APIs from Dbghelp.dll, which are used to resolve function addresses from symbol names. Another good API calls to search for are CreateToolhelp32Snapshot, EnumProcessModules, and C runtime APIs like fopen could be potentially used for leaking.**

In the OSED course we manage to leak via TCP the address of WriteProcessMemory by interacting with the SymGetSymFromName Windows API call. By reversing the application, we find that, by sending certain payload, we manage to leak any address of any library via TCP:
```
 /bin/python /home/kali/Documents/osed/aslr02_poc.py
b'\x00\x00\x00\x9eXpressServer: SymbolOperation \n------------------------------- \nValue of [WriteProcessMemory] is: \n\nAddress is: 0x76FA3AD0 \nFlags are: 0x207 \nSize is : 0x20 \n'
Leaked address = 0x76fa3ad0 
[+] Packet sent
```

This leak provides a direct ASLR bypass by resolving and returning the address of any exported function. 
Given that we have the mapped address of WriteProcessMemory, we can also know the base address of kernel32.dll (just by doing some mathematical operations), meaning that we could use ROP again inside kernel32.dll.
**Note: We will not do this as using ROP gadgets (memory address) from kernel32.dll is not very feasible for real exploits, as every monthly update changes kernel32.dll a little bit and that will displace our ROP chain, making our exploit dependant on the OS version. Remember that we want a very portable exploit.**

We can create a better exploit by leaking the address of a function from one of the IBM modules shipped with FastBackServer, meaning our exploit will only be dependent on the version of Tivoli.
We will locate a pointer to an IBM module that we can use for ROP gadgets to bypass DEP. 

# Searching our vulnerable module
Let's enumerate the modules used by the program and also the routes:
```
0:078> lm f
start    end        module name
001b0000 001ed000   SNFS     C:\Program Files\Tivoli\TSM\FastBack\server\SNFS.dll
00400000 00c0c000   FastBackServer C:\Program Files\Tivoli\TSM\FastBack\server\FastBackServer.exe
00ce0000 00d57000   CSFTPAV6 C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL
00d60000 00d8d000   libcclog C:\Program Files\Tivoli\TSM\FastBack\server\libcclog.dll
01190000 011c7000   CSNCDAV6 C:\Program Files\Tivoli\TSM\FastBack\server\CSNCDAV6.DLL
011d0000 01202000   CSMTPAV6 C:\Program Files\Tivoli\TSM\FastBack\server\CSMTPAV6.DLL
01210000 01243000   snclientapi C:\Program Files\Tivoli\TSM\FastBack\server\snclientapi.dll
01520000 01562000   NLS      C:\Program Files\Tivoli\TSM\FastBack\Common\NLS.dll
01590000 015bb000   gsk8iccs C:\Program Files\ibm\gsk8\lib\gsk8iccs.dll
01860000 0189a000   icclib019 C:\Program Files\ibm\gsk8\lib\N\icc\icclib\icclib019.dll
01a50000 01b40000   libeay32IBM019 C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll
64eb0000 64f53000   MSVCR90  C:\Windows\WinSxS\x86_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.9625_none_508ef7e4bcbbe589\MSVCR90.dll
66380000 663b0000   IfsUtil  C:\Windows\SYSTEM32\IfsUtil.dll
663b0000 663d7000   ulib     C:\Windows\SYSTEM32\ulib.dll
66b50000 66b5e000   fmifs    C:\Windows\SYSTEM32\fmifs.dll
67010000 67028000   ntlanman C:\Windows\System32\ntlanman.dll
67050000 67059000   drprov   C:\Windows\System32\drprov.dll
67060000 6706f000   browcli  C:\Windows\SYSTEM32\browcli.dll
670b0000 670ba000   DAVHLPR  C:\Windows\System32\DAVHLPR.dll
670c0000 670d9000   davclnt  C:\Windows\System32\davclnt.dll
670e0000 670ee000   cscapi   C:\Windows\SYSTEM32\cscapi.dll
671e0000 67219000   ActiveDS C:\Windows\SYSTEM32\ActiveDS.dll
672e0000 67317000   adsldpc  C:\Windows\SYSTEM32\adsldpc.dll
6a8b0000 6a8be000   winrnr   C:\Windows\System32\winrnr.dll
6a8c0000 6a8d6000   wshbth   C:\Windows\system32\wshbth.dll
6a8e0000 6a8f6000   pnrpnsp  C:\Windows\system32\pnrpnsp.dll
6aa80000 6aa91000   napinsp  C:\Windows\system32\napinsp.dll
6bc70000 6bf0b000   msi      C:\Windows\SYSTEM32\msi.dll
6c330000 6c4db000   dbghelp  C:\Windows\SYSTEM32\dbghelp.dll
6c4e0000 6c5ae000   CLUSAPI  C:\Windows\SYSTEM32\CLUSAPI.dll
6c5b0000 6c5ba000   Secur32  C:\Windows\SYSTEM32\Secur32.dll
6c600000 6c608000   WSOCK32  C:\Windows\SYSTEM32\WSOCK32.dll
6c630000 6c644000   NETAPI32 C:\Windows\SYSTEM32\NETAPI32.dll
6c650000 6c669000   MPR      C:\Windows\SYSTEM32\MPR.dll
6d920000 6d93d000   SRVCLI   C:\Windows\SYSTEM32\SRVCLI.DLL
6f150000 6f1a8000   fwpuclnt C:\Windows\System32\fwpuclnt.dll
6f1f0000 6f1f8000   rasadhlp C:\Windows\System32\rasadhlp.dll
6f2d0000 6f2d8000   VERSION  C:\Windows\SYSTEM32\VERSION.dll
6f3f0000 6f405000   SAMCLI   C:\Windows\SYSTEM32\SAMCLI.DLL
71550000 71566000   dhcpcsvc C:\Windows\SYSTEM32\dhcpcsvc.DLL
71f80000 71f96000   NLAapi   C:\Windows\system32\NLAapi.dll
73ce0000 73cef000   kernel_appcore C:\Windows\SYSTEM32\kernel.appcore.dll
73e70000 74487000   windows_storage C:\Windows\SYSTEM32\windows.storage.dll
74a70000 74aa1000   rsaenh   C:\Windows\system32\rsaenh.dll
74b60000 74b71000   WKSCLI   C:\Windows\SYSTEM32\WKSCLI.DLL
74c50000 74c79000   ntmarta  C:\Windows\SYSTEM32\ntmarta.dll
74d70000 74da2000   iphlpapi C:\Windows\SYSTEM32\iphlpapi.dll
74db0000 74e40000   DNSAPI   C:\Windows\SYSTEM32\DNSAPI.dll
74e40000 74e4b000   NETUTILS C:\Windows\SYSTEM32\NETUTILS.DLL
74e50000 74e83000   LOGONCLI C:\Windows\SYSTEM32\LOGONCLI.DLL
74ff0000 75047000   mswsock  C:\Windows\System32\mswsock.dll
75180000 7518a000   CRYPTBASE C:\Windows\SYSTEM32\CRYPTBASE.dll
75190000 751a3000   CRYPTSP  C:\Windows\SYSTEM32\CRYPTSP.dll
75230000 75255000   Wldp     C:\Windows\SYSTEM32\Wldp.dll
754c0000 754e9000   DEVOBJ   C:\Windows\SYSTEM32\DEVOBJ.dll
755b0000 755f7000   WINSTA   C:\Windows\System32\WINSTA.dll
75660000 75685000   SSPICLI  C:\Windows\SYSTEM32\SSPICLI.DLL
756d0000 756ec000   profapi  C:\Windows\SYSTEM32\profapi.dll
75870000 758cf000   bcryptPrimitives C:\Windows\System32\bcryptPrimitives.dll
75930000 75a50000   ucrtbase C:\Windows\System32\ucrtbase.dll
75a50000 75a8b000   cfgmgr32 C:\Windows\System32\cfgmgr32.dll
75a90000 75b0b000   msvcp_win C:\Windows\System32\msvcp_win.dll
75b10000 75bf6000   gdi32full C:\Windows\System32\gdi32full.dll
75c00000 75c1b000   bcrypt   C:\Windows\System32\bcrypt.dll
75c20000 75e57000   KERNELBASE C:\Windows\System32\KERNELBASE.dll
75ef0000 75f0d000   win32u   C:\Windows\System32\win32u.dll
75f10000 75f6d000   WLDAP32  C:\Windows\System32\WLDAP32.dll
75f70000 75ff7000   shcore   C:\Windows\System32\shcore.dll
760b0000 76146000   OLEAUT32 C:\Windows\System32\OLEAUT32.dll
76150000 761cd000   ADVAPI32 C:\Windows\System32\ADVAPI32.dll
761d0000 76450000   combase  C:\Windows\System32\combase.dll
765e0000 76757000   USER32   C:\Windows\System32\USER32.dll
76760000 7681f000   msvcrt   C:\Windows\System32\msvcrt.dll
76880000 76e5a000   SHELL32  C:\Windows\System32\SHELL32.dll
76e60000 76f43000   ole32    C:\Windows\System32\ole32.dll
76f50000 76f57000   NSI      C:\Windows\System32\NSI.dll
76f60000 76ffd000   KERNEL32 C:\Windows\System32\KERNEL32.DLL
77000000 77022000   GDI32    C:\Windows\System32\GDI32.dll
77030000 770a7000   sechost  C:\Windows\System32\sechost.dll
770b0000 770f5000   SHLWAPI  C:\Windows\System32\SHLWAPI.dll
77100000 77106000   PSAPI    C:\Windows\System32\PSAPI.DLL
77310000 773d3000   RPCRT4   C:\Windows\System32\RPCRT4.dll
773e0000 7781a000   SETUPAPI C:\Windows\System32\SETUPAPI.dll
77820000 77883000   WS2_32   C:\Windows\System32\WS2_32.dll
77890000 77a2f000   ntdll    C:\Windows\SYSTEM32\ntdll.dll
```

The output reveals ten IBM DLLs and the FastBackserver executable.
Next, we need to select a module with an exported function we can resolve **that contains desirable gadgets**. We must also ensure it does not contain 0x00 in the the base address, which excludes the use of FastBackServer.exe.

Multiple modules meet these requirements, so we’ll start by arbitrarily choosing libeay32IBM019.dll, located in C:\Program Files\ibm\gsk8\lib\N\icc\osslib.
Let's pick a function that **does not contain badchars** and leak its loaded address. For example, N98E_CRYPTO_get_net_lockid function.
This function is located at offset 0x14E0 inside the module.

We will do the following things to obtain the **base address (with ASLR) of libeay32IBM019**
- Obtain the loaded address of N98E_CRYPTO_get_new_lockid with ASLR.
- Substract the offset of N98E_CRYPTO_get_new_lockid to such loaded address. 
That is what we did:
Leaked address of the function inside the module = 0x1ca14e0 
Base address of libeay32IBM019: 0x1ca0000

# What happens if the loaded address has badchars
As always we must check if the base address had badchars.
Keeping this in mind, we have to execute the ASLR disclosure multiple times across application restarts and inspecting the upper two bytes of the module base address.
For example, if the base address of our module is 0x3200000, the address contains a badchar (0x20), so we have to restart the service. When restarted, the address is 0x3050000. For example, this address does not have badchars.
Note that in this specific application, there is a watchdog that, in case of a crash, it gets restarted automatically, so we can "bruteforce" a good valid address without badchars.
In other case, we might have to restart the application manually until the leaked base address is valid.

# DEP bypass via WriteProcessMemory
We have already seen how to modify the stack region to executable using the VirtualAlloc windows API call.
In this case, we will learn a different way of doing it: we will copy our shellcode from the stack (NX) to a pre-allocated module's code page by using the WriteProcessMemory API call.
We will copy our shellcode into the code page of the same module we leaked its base address, as we already have the base address leaked and finding the regions to store the code will be much easier.
The code page is already executable, so we won’t violate DEP when the shellcode is executed from there.


Let's see the arguments of the function by inspecting the function prototype:
```cpp
BOOL WriteProcessMemory( 
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer, SIZE_T nSize,
	SIZE_T *lpNumberOfBytesWritten );
```

## WriteProcessMemory argument crafting
- hProcess is the handle to the process we want to interact with. Since the API call will be performed from the context of our process, we don't need to supply a handle and we can supply a pseudo handle **Note: The pseudo handle is a special constant with the value -1 that, when used, indicates that the handle is a handle to the calling process.** This way we can add -1 and we avoid having to obtain a handle to our process.
- The second argument, lpBaseAddress, is the absolute memory address inside the code section where we want our shellcode to be copied. In principle, this address could be anywhere inside the code section because it has the correct memory protections, but overwriting existing code could cause the application to crash.
	- To avoid crashing the application, we need to locate unused memory inside the code section and copy our shellcode there. When the code for an application is compiled, the code page of the resulting binary must be page-aligned. If the compiled opcodes do not exactly fill the last used page, it will be padded with null bytes.
	- Exploit developers refer to this padded area as a **code cave**. The easiest way to find a code cave is to search for n**ull bytes at the end of a code section’s upper bounds**. Let’s begin our search by navigating the PE header364 to locate the start of the code pages.
**Note: We can find the offset to the PE header by dumping the DWORD at offset 0x3c from the MZ header**:
```c
0:077> dd libeay32iBM019+3c L1
02f7003c  00000108
```
Once we know this offset, we add 0x2C to the offset to find the **offset to the code section**:
```c
0:077> dd libeay32IBM019 + 108 + 2c L1 
031f0134 00001000

0:077> ? libeay32IBM019 + 1000
Evaluate expression: 49745920 = 02f71000
```
Once we are in the code section, let's check the address permissions and get information about such section:
```c
0:077> 
0:077> !address 02f71000

Usage:                  Image
Base Address:           02f71000
End Address:            03003000
Region Size:            00092000 ( 584.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000020          PAGE_EXECUTE_READ
Type:                   01000000          MEM_IMAGE
Allocation Base:        02f70000
Allocation Protect:     00000080          PAGE_EXECUTE_WRITECOPY
Image Path:             C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll
Module Name:            libeay32IBM019
Loaded Image Name:      
Mapped Image Name:      
More info:              lmv m libeay32IBM019
More info:              !lmi libeay32IBM019
More info:              ln 0x2f71000
More info:              !dh 0x2f70000


Content source: 1 (target), length: 92000

```

We know that it we reached the start of the code section because the "Base Address" value is the same than our calculated value
Note that the memory protection PAGE_EXECUTE_READ is active. **Note**: A typical code page is not writable, but WriteProcessMemory takes care of this by making the target memory page writable before the copy, then reverting the memory protections after the copy.

To locate a code cave, we can subtract a sufficiently-large value from the upper bound to find unused memory large enough to contain our shellcode.
We have to **take the end address and substract a large value.**
```c
0:077> dd 02f71000-400
03002c00  00000000 00000000 00000000 00000000
03002c10  00000000 00000000 00000000 00000000
03002c20  00000000 00000000 00000000 00000000
03002c30  00000000 00000000 00000000 00000000
03002c40  00000000 00000000 00000000 00000000
03002c50  00000000 00000000 00000000 00000000
03002c60  00000000 00000000 00000000 00000000
03002c70  00000000 00000000 00000000 00000000
```
0x400 should be enough to contain our shellcode and we can see that it's full of zeros, from 03002c70 to 03002c00. We now have a region to store our shellcode inside the module. Remember that the module address will change on boot via ASLR, so we will have to calculate these address dinamically.
As we have to calcule this address dinamically, let's see the offset from the base address of our module: libeay32IBM019
```c
0:077> ? 02f71000-400 - libeay32IBM019
Evaluate expression: 3072 = 00000c00
```

The code cave starts at offset c00 from the module. **This code cave address contains a null byte, so we will use the offset 00000c04 instead.**
Summarizing the information we gathered so far, we **can use offset 0x92c04 together with the leaked module base address** as the second argument (lpBaseAddress) to WriteProcessMemory.

Let's proceed with the three following argument:
- lpBuffer: The address of the memory region we want to copy. We want to copy our shellcode, which will be located on the stack after we trigger the vulnerability. We will calculate this later.
- nSize: The shellcode size. We can hardcode this value once we generate it and push it to the stack.
- `*lpNumberOfBytesWritten`: A pointer to a writable DWORD where WriteProcessMemory wil store the number of bytes that were copied. We could use a pointer to a stack address, but it is easier to use an address inside the **data section of our module as we do not have to calculate it at runtime:**
We can use the !dh command to find the data section’s start address to dump the name of the module along with all header information.
```c 
0:077> !dh -a libeay32IBM019

...

SECTION HEADER #4
   .data name
    F018 virtual size
   D5000 virtual address
    CA00 size of raw data
   D2000 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
C0000040 flags
         Initialized Data
         (no align specified)
         Read Write

```

We know that the offset to the data section is 0xD5000, and its size is 0xF018. Before using this address we must verify that the address does not have contents and that the memory protections are at least writable (we just need to store things, not execute them).
