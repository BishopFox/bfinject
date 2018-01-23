# bfinject
Dylib injection for Jailbroken 64-bit iOS 11.0 - 11.1.2 (only LiberiOS has been tested).

Can inject arbitrary .dylibs into running App Store apps, and has built-in support for iSpy, Cycript, and app decryption. This is all self-contained and does not use QiLin.

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
* Type `bash bfinject` for help
* NOTE: it's important to precede the command with `bash` or it won't work. Sandbox yadda yadda.
```
-bash-3.2# bash bfinject
Syntax: bfinject -p PID <[-l /path/to/yourdylib] | [-L feature]>

For example:
   bfinject -p 1234 -L cycript               # Injects Cycript into PID, listening on port 1337
     or
   bfinject -p 4566 -l /path/to/evil.dylib   # Injects the .dylib of your choice

Available features:
  cycript    - Inject and run Cycript. Use cycript -r <deviceIP>:1337
  decrypt    - Create a decrypted copy of the target app
  test       - Inject a simple .dylib to make an entry in the console log
  iSpy       - Inject iSpy. Browse to http://<DEVICE_IP>:31337/
```

## Decrypt App Store apps
Here's an example decrypting the app running with PID 802:

```
-bash-3.2# pwd
/var/bfinject
-bash-3.2# bash bfinject -p 802 -L decrypt
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

Check the console log for the device, it will tell you where the decrypted IPA is stored. For example:

```
[dumpdecrypted] Wrote /var/mobile/Containers/Data/Application/6E6A5887-8B58-4FC5-A2F3-7870EDB5E8D1/Documents/decrypted-app.ipa
```

Getting the .ipa off the device can be done with netcat. On your laptop:

```
ncat -l 0.0.0.0 12345 > decrypted.ipa
```

And on the jailbroken device:

```
cat /path/to/decrypted.ipa > /dev/tcp/<IP_OF_YOUR_COMPUTER>/12345
````

The .ipa will be a clone of the original .ipa from the App Store, except that the main binary and all its accompanying frameworks and shared libraries will be decrypted. The CRYPTID flag will be 0 in each previously-encrypted file. You can take the .ipa, extract the app, modify it as needed, re-sign it with your own developer cert, and deploy it onto non-jailbroken devices as needed.

## Cycript
One of bfinject's features is to incorporate common pentesting tools, like Cycript. More will be added with time. To use Cycript you will need the Cycript command-line client installed on your MacBook (http://www.cycript.org/). Then, once bfinject is installed on your test device, do this to inject Cycript into your target process:

```
-bash-3.2# bash bfinject -p <PID_OF_APP> -L cycript
[+] Injecting into '/var/containers/Bundle/Application/DD0F3B57-555E-4DDE-B5B0-95E5BA567C5C/Redacted.app/Redacted'
...magic happens...
[+] So long and thanks for all the fish.
```

Once Cycript has been injected, you can connect to it from your MacBook like this:

```
carl@calisto ~/bin $ ./cycript -r <IP_OF_YOUR_DEVICE>:1337
cy# [[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path]
@"/var/mobile/Containers/Data/Application/169C799E-5166-4BF8-AE01-FC9F14684A34/Documents"
```

## How does it work?
At a high level, it side-loads a self-signed .dylib into a running Apple-signed App Store app like this:

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
  * _pthread_set_self is called in order to setup threading for dlopen()
  * dlopen() is called to inject our evil shared library  
  * dlopen() will RET to the value in the $lr register, which is another RET instruction  
  * RET will return to RET will return to RET... ad infinitum  
* Poll the thread's registers to check for $pc == address of ROP gadget (the RET instruction)
* Once the gadget is hit, terminate the thread, free the memory, job done.

For a low-level description, see the source.

## Known issues
* None

## Credits
* Stefan Esser (10n1c) for the original ideas and code behind dumpdecrypted (https://github.com/stefanesser/dumpdecrypted/blob/master/dumpdecrypted.c)
* Dmitry Rodionov for lorgnette (https://github.com/rodionovd/liblorgnette/)
* Jonathan Levin for the  LiberiOS jailbreak (http://newosxbook.com/liberios/)
* Ian Beer for the async_wake exploit (https://bugs.chromium.org/p/project-zero/issues/detail?id=1417)
* Apple for a great mobile OS
