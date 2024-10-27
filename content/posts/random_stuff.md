+++
title = 'Random stuff'
date = 2024-02-28T20:53:30+01:00
draft = false
showDate = true
toc = true
tags = ["evasion", "loader", "firststeps", "maldev"]
+++

Custom function declaration. Used when hooking, to get a pointer to the original function to get it dinamically resolved via IAT and then override this pointer, or to craft a new function that points to a shellcode with the function behavior (used in reflective DLL shellcode)

**Case of getting the function pointer to a resolving Windows API call:**
```c++
// Declaring the function pointer to a resolving Windows API call
int (WINAPI* pToUnicodeEx) (UINT wVirtKey,  UINT wScanCode, const BYTE *lpKeyState, LPWSTR pwszBuff, int cchBuff, UINT wFlags, HKL dwhkl) = ToUnicodeEx;

// Call the function using its pointer
pToUnicodeEx(wVirtKey, wScanCode, lpKeyState, pwszBuff, cchBuff, wFlags, dwhkl);
```

**Case of getting the function pointer to a memory zone where the function is implemented via shellcode:**
``` c++
// Declaring the function pointer to a resolving Windows API call
typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );

// Declaring the function pointer instance to NULL
EXECUTEX64 pExecuteX64   = NULL;

// Allocating function for the function pointer
pExecuteX64 = (EXECUTEX64)VirtualAlloc( NULL, sizeof(sh_executex64), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );

// Copying the shellcode to the function pointer location
memcpy( pExecuteX64, sh_executex64, sh_executex64_len );

// Call the function using its pointer
pExecuteX64( pX64function, (DWORD)ctx );
```
