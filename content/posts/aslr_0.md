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

This is the exploit that manages to leak 
