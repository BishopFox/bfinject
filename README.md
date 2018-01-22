# bfinject
Dylib injection for 64-bit iOS 11.x.y jailbroken (LiberiOS 11.0.1 tested) devices where x <= 1. Incorporates a .dylib that can be used to decrypt entire iOS apps and corresponding frameworks and generate clean, unencrypted .ipa files of App Store apps.

## Use
* Jailbreak your iOS 11.0 - 11.1.2 device with http://newosxbook.com/liberios/ 
* Copy the bfinject tarball, https://github.com/BishopFox/bfinject/raw/master/bfinject.tar, onto your jailbroken device:
```
ssh root@your-device-ip # (the password is 'alpine')
export PATH=$PATH:/jb/usr/bin:/jb/bin:/jb/sbin:/jb/usr/sbin:/jb/usr/local/bin:
cd /jb/usr/bin/
wget https://github.com/BishopFox/bfinject/raw/master/bfinject.tar
tar xvf bfinject.tar
cp bfdecrypt.dylib /System/Library/Frameworks/bfdecrypt.framework/
```
* Launch the target app
* Find your app's PID using `ps`
* Type `bash bfinject PID /System/Library/Frameworks/bfdecrypt.framework/bfdecrypt.dylib`
* NOTE: it's important to precede the command with `bash` or it won't work. Sandbox yadda yadda.
* Magic happens:
```
[+] Injecting into '/var/containers/Bundle/Application/FAA7A073-BF70-4181-890E-B50112529289/SPG.app/SPG'
[+] Getting Team ID from target application...
[+] Signing injectable .dylib with Team ID 722QAVZ8WW and platform entitlements...
[+] Injecting dumpdecrypted.dylib into target application, PID 2463
[bfinject] Injecting bfdecrypt.dylib into PID 2463...
gadget candidate: 0x10464957c ... unaligned, skipping
gadget candidate: 0x1051a147c ... unaligned, skipping
gadget candidate: 0x105246c48 ... unaligned, skipping
gadget candidate: 0x105429224 ... unaligned, skipping
gadget candidate: 0x105444440 ...
Infinite loop RET gadget found @ 0x105444440
Fake stack frame is 128000 bytes at 0x109260000 in remote proc
get_injectable_thread: found 11 threads, suspending them all.
Sleeping...
Back!
Saved state:
$pc = 0x180d9cbc4
$sp = 0x16b7bac10
$x0 = 0x10004005
Desired function 'dlopen' is at 0x180c8f460
Setting registers with destination function
Processing 's' argument
s: ////////////////System/Library/Frameworks/bfdecrypt.framework/bfdecrypt.dylib
x0: 0x109260000
 ('////////////////System/Library/Frameworks/bfdecrypt.framework/bfdecrypt.dylib')
Resuming thread with hijacked regs
Waiting for thread to hit the infinite loop gadget...
pc: 0x180dbc450
lr: 0x180db5c8c
sp: 0x109269e80

...stuff...

pc: 0x105444440
lr: 0x105444440
sp: 0x10926fa00


We hit the infinite loop, call complete. Restoring stack and registers.
resume_all_threads: found 11 threads, resuming them all.
And we're done. x0 = 0x1c41fd500
[bfinject] dlopen() returned 0x1c41fd500
[+] So long and thanks for all the fish.
```
* Check the console log for the device, it will tell you where the decrypted IPA is stored:
`[dumpdecrypted] Wrote /var/mobile/Containers/Data/Application/6E6A5887-8B58-4FC5-A2F3-7870EDB5E8D1/Documents/decrypted-app.ipa`

## Credits
* Stefan Esser (10n1c) for the original ideas and code behind dumpdecrypted (https://github.com/stefanesser/dumpdecrypted/blob/master/dumpdecrypted.c)
* Dmitry Rodionov for lorgnette (https://github.com/rodionovd/liblorgnette/)
* Jonathan Levin for the  LiberiOS jailbreak (http://newosxbook.com/liberios/)
* Ian Beer for the async_wake exploit (https://bugs.chromium.org/p/project-zero/issues/detail?id=1417)
* Apple for a great mobile OS

## How does it work?
In stages. Seriously. The iOS ecosystem is batshit crazy with a bajillion technical controls to mitigate exploits. 

First, some history. Ian Beer dropped his "async_wait" exploit that gets task_for_pid zero (aka "tfp0"), which is a magical port into the kernel where you can get it to do stuff for you, which is nice when circumventing security controls.

Jonathan Levin took async_wait and built a proof-of-concept jailbreak called LiberiOS, which gives us a working root SSH shell on iPhones (actually any modern iPhone/iPad). LiberiOS makes it possible to run self-signed binaries and load self-signed shared libraries, so long as we do some careful code signing. LiberiOS does this by patching the Apple Mobile File Integry daemon, "amfid", which does the duty of verifying the codesigning integrity of executable code loaded from files (mach-o binaries, shared libraries, frameworks, etc). 

But that's only userland. There are also codesigning checks in the kernel itself (ok, kexts), and those aren't patched because of KPP: kernel patch protection. It's sophisticated introspection built into the kernel to detect and defeat modifications to itself; I believe on modern phones there's some hardware support, too, but much Googling required for that. It's really hard to break, which is why currently only the userland half of codesigning is broken on iOS11. Which gives us some restrictions on what we can do with a jailbreak. 

For example, there's an idiosyncrasy that makes it impossible to directly run shell scripts. Instead of `./script.sh` you have to run `bash ./script.sh`. Wut. 

Worse than that, we can't launch App Store apps from the command-line because only SpringBoard has entitlements to do that, and there's no known bypass right now. This means we can't do all our favorite DYLD_LOAD_LIBRARIES tricks to preload malicious shared libraries into applications at launch time. 

This one issue breaks Cydia, MobileSubstrate, iSpy, Frida, Cycript, Fishhook and any other hack you've ever used to sideload code into an App Store app.

Not all was lost though, because Levin hinted at another means of shared library injection: 
`Arbitrary Dylib loading works. NO, CYDIA SUBSTRATE WON'T. Not my problem - @Saurik owns this one`

Yeah well, despite some work on Electra and random forks of Ian Beer's exploit, nobody has come up with a nice, simple way of injecting arbitrary dylibs into App Store apps. So I decided to kill two birds with one stone: brush up my ROP on arm64 and build an injection framework to bring back our favorite toys. And here we are.

## Ok, really. How does it work?
It side-loads a self-signed .dylib into a running Apple-signed App Store app.

### Three main challenges
* Attach to another process and manipulate it. Easy: we get this for free with LiberiOS.
* Execute arbitrary code in the attached process. Hard. Non-exec stack, heap, everything; kernel virtual memory protection against setting VM_PROT_EXECUTE on a page if it's ever been VM_PROT_WRITE, yadda yadda. We're left with thread manipulation and ROP tricks, but that's enough to do the job.
* Load a self-signed library into an Apple-signed process. Turns out quite easy with a small trick.

### Attach to another process
We can use `task_for_pid()` like this to get a task port on another process, thanks to LiberiOS:

```
mach_port_t task;
int pid = 1234; // whatever

int kret = task_for_pid(mach_task_self(), pid, &task);
if(kret != KERN_SUCCESS)
  printf("task_for_pid() failed with message %s!\n", mach_error_string(kret));
```

With `task` we can get a list of all the threads in a process:

```
thread_act_port_array_t threadList;
mach_msg_type_number_t threadCount;

kret = task_threads(task, &threadList, &threadCount);
if (kret!=KERN_SUCCESS)
  printf("get_injectable_thread: task_threads() failed with message %s!\n", mach_error_string(kret));
```

With that, all the threads can be suspended:

```
for(int i = 0; i < threadCount; i++) {
  thread_suspend(threadList[i]);
  thread_abort_safely(threadList[i]);
}
```

With the threads suspended, we can query the registers of each thread:

```
arm_thread_state64_t state;
mach_msg_type_number_t stateCount;

kret = thread_get_state(threadList[0], ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount);
if (kret!=KERN_SUCCESS)
  printf("get_thread_state: thread_get_state() failed with message %s!\n", mach_error_string(kret));

printf("$pc = 0x%llx\n$lr = 0x%llx\n$fp = 0x%llx\n$sp%llx\n", state.__pc, state.__lr, state.__fp, state.__sp);
for(int i = 0; i <= 28; i++)
    printf("$x%d = 0x%llx\n", i, state.__x[i]);
```

Which produces something like:

```
$pc = 0x180d9cbc4
$lr = 0x180db5c8c
$fp = 0x181155ea0
$sp = 0x16b7bac10
$x0 = 0x10004005
..
$x28 = 0x105429220
```

Not content with querying the registers of any given thead, it's possible to set the registers and resume the thread, which 
means execution can be redirected to any code in memory, such as app code, app-bundled frameworks, or Apple frameworks. At this point we're essentially crafting a ROP exploit: allocate memory pages in the remote process, setup a fake stack frame, then redirect execution to a suitable gadget or library call. The code is simple, for example this will cause a thread to throw an access violation due to setting the PC register to 0xdeadbeef:

```
thread_suspend(thread);
thread_abort_safely(thread);
state.__pc = 0xdeadbeef; // this will cause SIGSEGV trying to run code at address 0xdeadbeef
thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
```

### Execute arbitrary code in the target process
This is fairly straight-forward once you exclude all the ways it _can't_ be done. For example:
* vm_allocate() a new page in the target, then vm_protect(VM_PROT_WRITE) it, then write shellcode, then vm_protect(VM_PROT_READ|VM_PROT_EXECUTE), then execute the code. Doesn't work because mmap won't honor requests for executable pages if the page was _ever_ marked writeable.
* Rewriting data structures to affect code flow. This is too hard because such attacks would be highly application-specific. Nope.
* Modifying application binaries on the filesystem. Nope, codesigning checks will break this.
* Attaching a debugger and doing... stuff... might work, didn't try.

Instead I went for this approach:

* Suspend all the threads in the target process
* Pick a thread to hijack. I used thread zero, the main UI thread
* Save the state of all the CPU registers for the thread
* Allocate some memory pages in the remote process for a new temporary stack
* Place the string "/path/to/my.dylib" at known location in stack
* Use some tricks to lookup the address of dlopen() in the remote process
* Find a simple RET ROP gadget in an executable page (RET = "\xc0\x03\x5f\xd6" on arm64)
* Set CPU registers for the thread: 
  * $pc = Address of dlopen()  
  * $x0 = Parameter 1 of dlopen: address of string "/path/to/dylib" in temporary stack  
  * $x1 = Parameter 2 of dlopen: the value RTLD_LAZY | RTLD_GLOBAL  
  * $sp = Middle of the temporary stack  
  * $fp = Quarter way into the temporary stack  
  * $lr = Address of ROP gadget  
* Resume the thread. The following will happen:
  * dlopen() will run and our library will be injected  
  * dlopen() will RET to the value in the $lr register, which is another RET instruction  
  * RET will return to RET will return to RET... ad infinitum  
* Poll the thread's registers every .5 seconds and check for $pc == address of ROP gadget (the RET instruction)
* Pause the thread
* Restore the CPU registers
* Resume all of the threads
* Job done

## Known issues
* Code is janky.
* There are probably easier ways of doing this, but nobody's done them yet as far as I can tell, so here you are.
