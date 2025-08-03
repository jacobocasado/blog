The prologue is the one in charge of creating the canary and adding it to 
the stack.
The epilogue is the one in charge of comparing the canary.


STACK
RET ADDRESS -> 0xffffffff
BASE EBP
CANARY
VALUE -> 0x00000000

Canary is after base ebp and ret address to guard them both.
Canary first byte is always null byte -> with printf you can’t leak the 
canary.
Libc stores canary info in its own memory space, unless threads are 
created.
*** NOTE: Libc calls main so the return address from libc (which will be 
exit most of the time) will be in the stack if we go deep enough.
Ideas to bypass stack canary:
- Leak the canary value from the stack
- Overwrite the stored canary value from libc
- Non-linear overflow (arr[I] = value)
- Brute forcing > Not feasible as it is 8 bytes and program crashes
- If process is fork-based and spawns children we can guess 1 by 1 the 
value as libc copies all memory.
- Threads do not share stack although they share some memory as they are 
inside the same process. TLS is stored at the start of the stack so we can 
override the canary value and the stored canary from TLS.


Guard pages -> Between each thread stack so you can’t attack one thread 
from another.
