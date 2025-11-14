In Linux operating systems, the function prologue is the one in charge of creating the canary and adding it to the stack.
The epilogue is the one in charge of comparing the canary.

Let's see the stack layout:
```
[...] -> 0xffffffff
RET ADDRESS 
BASE EBP
CANARY
VALUE -> 0x00000000
```

Canary is after base EBP and return address, in order to guard them both.
Note: Canary first byte is always null byte -> **The printf function cannot be exploited to leak the canary.**
**Libc stores canary info in its own libc memory space**, unless threads are created. In that case, the canary is independent per thread and each thread has its own stack canary.

**Ideas to bypass stack canary:**
- Leak the canary value from the stack
- Overwrite the stored canary value from libc
- Non-linear overflow (arr[I] = value) that allows us to write in region without having to go through canary.
- Brute forcing > Not feasible as canary is 8 bytes and program will crash and not restart most of the time.
- If process is **fork-based** and spawns children we can guess 1 by 1 the value as **libc copies all memory.** The canary value will be the same each time (fork copies memory regions).
- Threads do not share stack although they share some memory as they are inside the same process. TLS is stored at the start of the stack so we can  override the canary value and the stored canary from TLS.
	- Guard pages -> Memory pages between each thread stack so you can’t attack one thread from another.

# How to leak libc base address to bypass ASLR
Note: libc calls our "main" function, so the return address from libc (which will be 
**exit** most of the time) will be in the stack if we go deep enough.
With the "exit" return address or any function return address from libc, we can get libc base address (Use [this tool](https://libc.rip/) for that purpose).
