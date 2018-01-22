# bfinject
Dylib injection for 64-bit iOS 11.x.y jailbroken (LiberiOS 11.0.1 tested) devices where x <= 1. Incorporates a .dylib that can be used to decrypt entire iOS apps and corresponding frameworks and generate clean, unencrypted .ipa files of App Store apps.

## Use
* Jailbreak your iOS 11.0 - 11.1.2 device with http://newosxbook.com/liberios/ 
* Copy the bfinject tarball, https://github.com/BishopFox/bfinject/raw/master/bfinject.tar, onto your LiberiOS jailbroken device:
```
ssh root@your-device-ip # (the password is 'alpine')
export PATH=$PATH:/jb/usr/bin:/jb/bin:/jb/sbin:/jb/usr/sbin:/jb/usr/local/bin:
cd /jb
mkdir bfinject
cd bfinject
wget http://<your_server>/bfinject.tar
wget http://<your_server>/evil.dylib
tar xvf bfinject.tar
```
* Launch the target app
* Find your app's PID using `ps`
* Type `bash bfinject <PID> <your.dylib>`
* NOTE: it's important to precede the command with `bash` or it won't work. Sandbox yadda yadda.
* Magic happens:
```
-bash-3.2# pwd
/var/bfinject
-bash-3.2# bash bfinject 802 ./bfdecrypt.dylib
[+] Injecting into '/var/containers/Bundle/Application/DD0F3B57-555E-4DDE-B5B0-95E5BA567C5C/redacted.app/redacted'
[+] Getting Team ID from target application...
[+] Signing injectable .dylib with Team ID REDACTED and platform entitlements...
[+] Injecting bfdecrypt.dylib into target application, PID 802
[bfinject] Getting tfp.
[bfinject] Creating new remote thread
[bfinject] Thread ID: 3075 (0xc03)
[bfinject] Looking for RET gadget in the target app...
             gadget candidate: 0x1006de618 ... Found @ 0x1006de618
[bfinject] Fake stack frame is 536870912 bytes at 0x10d2f8000 in remote proc
[bfinject] Looking for '_pthread_set_self' in the target process...
[bfinject] Desired function '_pthread_set_self' is at 0x184323804
[bfinject] Setting registers with destination function
[bfinject] New CPU state:
             $pc = 0x184323804
             $sp = 0x1252f8000
             $x0 = 0x0
             $x1 = 0x0
             $x2 = 0x0
             $x3 = 0x0
[bfinject] Resuming thread with hijacked regs
[bfinject] Waiting for thread to hit the infinite loop gadget...
[bfinject] We hit the infinite loop, call complete. Restoring stack and registers.
[bfinject] Looking for 'dlopen' in the target process...
[bfinject] Desired function 'dlopen' is at 0x1840e3460
[bfinject] Setting registers with destination function
[bfinject] New CPU state:
             $pc = 0x1840e3460
             $sp = 0x1252f8000
             $x0 = 0x0
             $x1 = 0x0
             $x2 = 0x0
             $x3 = 0x0
[bfinject] Resuming thread with hijacked regs
[bfinject] Waiting for thread to hit the infinite loop gadget...
[bfinject] We hit the infinite loop, call complete. Restoring stack and registers.
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
It side-loads a self-signed .dylib into a running Apple-signed App Store app like this:

* Allocate some memory pages in the remote process for a new temporary stack
* Place the string "/path/to/my.dylib" at known location in stack
* Use some tricks to lookup the address of dlopen() in the remote process
* Find a simple RET ROP gadget in an executable page (RET = "\xc0\x03\x5f\xd6" on arm64)
* Create a new thread in the target process
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
* Poll the thread's registers to check for $pc == address of ROP gadget (the RET instruction)
* Once the gadget is hit, terminate the thread, free the memory, job done.

## Known issues
* None
