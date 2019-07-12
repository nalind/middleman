# middleman
An experiment with seccomp-bpf

Is it possible to use seccomp filters to run multiple processes as one user,
while fooling them into thinking that they are running under multiple UIDs?

This might be useful for building container images as an unprivileged user, in
scenarios where creating a user namespace, using helper tools like
`newuidmap(1)` and `newgidmap(1)` to map multiple real UIDs and GIDs for use,
aren't an option.  It's been done by using `ptrace(2)`, but a process can only
be traced by one other process at a time, so processes which are run in this
way can't also be debugged using tools like `strace(1)` and `gdb(1)`.

After reading through the [original
paper](http://www.tcpdump.org/papers/bpf-usenix93.pdf), [the kernel's general
eBPF
docs](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/networking/filter.txt),
and [the seccomp-bpf
docs](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
(which even flat-out say that seccomp-bpf is not a sandboxing tool), we can
load a filter that will intercept calls to `getuid(2)` and `getgid(2)` as a
test.

A BPF filter is an array of opcodes, and those can be constructed using macros
from `<linux/filter.h>` and `<linux/bpf_common.h>`, or compiled from assembly
language down to bytecode using the kernel's `bpf_asm` tool, or from C using
`clang`'s `-march=bpf` flag.  In here we use the macros to avoid adding other
tools as build-time requirements.

The filter tells the kernel to notify a userspace listener for the specific
syscalls that we're interested in, and the userspace notifier supplies the
returned value (fake values that we supply) and an errno.  The helper should
have the privileges needed for opening the /proc/self/mem of the process that
called the syscall, and it can use that to read and write the contents of
arguments that are passed to the syscall as pointers.  This gives us a way to
read the names of files passed to syscalls like `stat(2)`, and to completely
control the values that are written to the `struct stat` that the calling
process wanted.

This is all pretty great.

Then we move on to `open(2)`, which returns a descriptor to its caller.  One
thing a userspace helper _can't_ do is tell the kernel to continue processing
the syscall, since the current filtering hook returns immediately after the
kernel receives the return values from the userspace helper.  This means that
if we wanted to correctly fake permissions checks in `open(2)`, we have to
return the descriptor value ourselves.  Of course, the returned value needs to
be the lowest not-currently-in-use descriptor number for the process, and once
we solved that, we'd have to handle `read(2)` and `write(2)` for that
descriptor, which eventually leads us to realizing that we'd have to handle
_all_ of the process's I/O ourselves, and that's more complexity than we're
looking to implement, so this is where we stop.
