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

## Known issues
* Code is janky.
* There are probably easier ways of doing this, but nobody's done them yet as far as I can tell, so here you are.
