# bfinject
Easy dylib injection for jailbroken 64-bit iOS 11.0 - 11.1.2. Compatible with Electra and LiberiOS jailbreaks.

bfinject loads arbitrary dylibs into running App Store apps. It has built-in support for decrypting App Store apps, and comes bundled with iSpy and Cycript.

bfinject is a wrapper that takes care of correctly codesigning your dylibs before injecting them using `bfinject4realz`. It's completely standalone, doesn't require jailbreakd, QiLin, or anything like that. It just works. 

**Note**: bfinject does not work on Electra if "Tweaks" is enabled. Reboot and re-run Electra without tweaks in order to use bfinject. If you see errors with "thread_create", this is the problem.

**Note**: bfdecrypt is available as a standalone dylib here: https://github.com/BishopFox/bfdecrypt/

## Navigate
* [Electra setup](https://github.com/BishopFox/bfinject/blob/master/README.md#electra-setup)
* [LiberiOS setup](https://github.com/BishopFox/bfinject/blob/master/README.md#liberios-setup)
* [Using bfinject](https://github.com/BishopFox/bfinject/blob/master/README.md#using-bfinject)
* [Testing bfinject](https://github.com/BishopFox/bfinject/blob/master/README.md#a-simple-test)
* [Decrypting App Store apps](https://github.com/BishopFox/bfinject/blob/master/README.md#decrypt-app-store-apps)
* [Cycript](https://github.com/BishopFox/bfinject/blob/master/README.md#cycript)
* [How does it work?](https://github.com/BishopFox/bfinject/blob/master/README.md#how-does-it-work)
* [Known issues](https://github.com/BishopFox/bfinject/blob/master/README.md#known-issues)
* [Credits](https://github.com/BishopFox/bfinject/blob/master/README.md#credits)

## Electra Setup
* Jailbreak your iOS 11.0 - 11.1.2 device with Electra >= b7
* Copy the bfinject tarball, https://github.com/BishopFox/bfinject/raw/master/bfinject.tar, onto your jailbroken device. You might need to copy it to your laptop first because Github enforces SSL, but the Electra version of `wget` doesn't support SSL.
```
ssh root@your-device-ip # (the password is 'alpine')
mkdir bfinject
cd bfinject
wget http://<your_server>/bfinject.tar
tar xvf bfinject.tar
```

## LiberiOS Setup
* Jailbreak your iOS 11.0 - 11.1.2 device with LiberiOS >= 11.0.3
* Copy the bfinject tarball, https://github.com/BishopFox/bfinject/raw/master/bfinject.tar, onto your jailbroken device. You might need to copy it to your laptop first because Github enforces SSL, but the LiberiOS version of `wget` doesn't support SSL.
```
ssh root@your-device-ip # (the password is 'alpine')
export PATH=$PATH:/jb/usr/bin:/jb/bin:/jb/sbin:/jb/usr/sbin:/jb/usr/local/bin:
cd /jb
mkdir bfinject
cd bfinject
wget http://<your_server>/bfinject.tar
tar xvf bfinject.tar
```

## Using bfinject
* Launch the target app into which you will inject your shared library
* Type `bash bfinject` for help
* NOTE: it's important to precede the command with `bash` or it won't work. Sandbox yadda yadda.
```
-bash-3.2# bash bfinject
Syntax: bfinject [-p PID | -P appname] [-l /path/to/yourdylib | -L feature]

For example:
   bfinject -P Reddit.app -l /path/to/evil.dylib   # Injects evil.dylib into the Reddit app
     or
   bfinject -p 1234 -L cycript                     # Inject Cycript into PID
     or
   bfinject -p 4566 -l /path/to/evil.dylib         # Injects the .dylib of your choice into PID

Instead of specifying the PID with -p, bfinject can search for the correct PID based on the app name.
Just enter "-P identifier" where "identifier" is a string unique to your app, e.g. "fing.app".

Available features:
  cycript    - Inject and run Cycript
  decrypt    - Create a decrypted copy of the target app
  test       - Inject a simple .dylib to make an entry in the console log
  ispy       - Inject iSpy. Browse to http://<DEVICE_IP>:31337/
```

## A Simple Test
Before doing anything more complex, test that it works. bfinject has built-in self tests. Here's an example using the Reddit app as the target:

```
Cs-iPhone:~ root# bash bfinject -P Reddit -L test
[+] Electra detected.
[+] Injecting into '/var/containers/Bundle/Application/55C94FAA-A282-4FDC-967D-6A012D01087E/Reddit.app/Reddit'
[+] Getting Team ID from target application...
[+] Thinning dylib into non-fat arm64 image
[+] Signing injectable .dylib with Team ID 2TDUX39LX8 and platform entitlements...
[bfinject4realz] Calling task_for_pid() for PID 486.
[bfinject4realz] Calling thread_create() on PID 486
[bfinject4realz] Looking for ROP gadget... found at 0x1019a2ba0
[bfinject4realz] Fake stack frame at 0x12ac5c000
[bfinject4realz] Calling _pthread_set_self() at 0x182bfb814...
[bfinject4realz] Returned from '_pthread_set_self'
[bfinject4realz] Calling dlopen() at 0x1829bb460...
[bfinject4realz] Returned from 'dlopen'
[bfinject4realz] Success! Library was loaded at 0x1c016e1c0
[+] So long and thanks for all the fish.
```

On the device screen you should see this:

<img src="https://i.imgur.com/4M9E07S.png" width="400px"/>

If not, something is broken ;)

## Decrypt App Store apps
Here's an example decrypting the Reddit app on an Electra-jailbroken iPhone:

```
Cs-iPhone:~ root# bash bfinject -P Reddit -L decrypt
[+] Electra detected.
[+] Injecting into '/var/containers/Bundle/Application/BCEBDD64-6738-45CE-9B3C-C6F933EA0793/Reddit.app/Reddit'
[+] Getting Team ID from target application...
[+] Thinning dylib into non-fat arm64 image
[+] Signing injectable .dylib with Team ID 2TDUX39LX8 and platform entitlements...
[bfinject4realz] Calling task_for_pid() for PID 3218.
[bfinject4realz] Calling thread_create() on PID 3218
[bfinject4realz] Looking for ROP gadget... found at 0x1016a5110
[bfinject4realz] Fake stack frame at 0x10a06c000
[bfinject4realz] Calling _pthread_set_self() at 0x181303814...
[bfinject4realz] Returned from '_pthread_set_self'
[bfinject4realz] Calling dlopen() at 0x1810c3460...
[bfinject4realz] Returned from 'dlopen'
[bfinject4realz] Success! Library was loaded at 0x1c03e1100
[+] So long and thanks for all the fish.
```

You'll see this screen on your device:

<img src="https://i.imgur.com/z8HkeIB.png" width="400px"/>

Once it's complete, you'll be presented with a UI alert to ask if you want to spawn a service from which you can download your decrypted IPA:

<img src="https://i.imgur.com/cf30n2L.png" width="400px"/>

If you tap `Yes`, a service will be spawned on port 31336 of your device. Connect to it and you'll be sent a raw copy of the IPA that can be downloaded with netcat like so:

```bash
carl@calisto-3 /tmp $ nc 192.168.1.33 31336 > decrypted.ipa
carl@calisto-3 /tmp $ ls -l decrypted.ipa
-rw-r--r--  1 carl  wheel  14649063 Jan 25 16:57 decrypted.ipa
carl@calisto-3 /tmp $ file decrypted.ipa
decrypted.ipa: iOS App Zip archive data, at least v2.0 to extract
```

Alternatively, check the console log for the device, it will tell you where the decrypted IPA is stored. For example:

```
[dumpdecrypted] Wrote /var/mobile/Containers/Data/Application/6E6A5887-8B58-4FC5-A2F3-7870EDB5E8D1/Documents/decrypted-app.ipa
```

You can also search the filesystem for the IPA like so:

```
find /var/mobile/Containers/Data/Application/ -name decrypted-app.ipa
```

Getting the .ipa off the device can be done with netcat. On your laptop, set up a listener service:

```
ncat -l 0.0.0.0 12345 > decrypted.ipa
```

And on the jailbroken device:

```
cat /path/to/decrypted.ipa > /dev/tcp/<IP_OF_YOUR_COMPUTER>/12345
````

The .ipa will be a clone of the original .ipa from the App Store, except that the main binary and all its accompanying frameworks and shared libraries will be decrypted. The CRYPTID flag will be 0 in each previously-encrypted file. You can take the .ipa, extract the app, modify it as needed, re-sign it with your own developer cert, and deploy it onto non-jailbroken devices as needed.

## Cycript
One of bfinject's features is to incorporate common pentesting tools, like Cycript. More will be added with time. To use Cycript you will need the Cycript command-line client installed on your MacBook (http://www.cycript.org/). Then, once bfinject is installed on your test device, do something like this example in which we inject Cycript into the Reddit app:

```
Cs-iPhone:~ root# bash bfinject -P Reddit -L cycript
[+] Electra detected.
[+] Injecting into '/var/containers/Bundle/Application/55C94FAA-A282-4FDC-967D-6A012D01087E/Reddit.app/Reddit'
[+] Getting Team ID from target application...
[+] Thinning dylib into non-fat arm64 image
[+] Signing injectable .dylib with Team ID 2TDUX39LX8 and platform entitlements...
[bfinject4realz] Calling task_for_pid() for PID 486.
[bfinject4realz] Calling thread_create() on PID 486
[bfinject4realz] Looking for ROP gadget... found at 0x1019a2ba0
[bfinject4realz] Fake stack frame at 0x10ab00000
[bfinject4realz] Calling _pthread_set_self() at 0x182bfb814...
[bfinject4realz] Returned from '_pthread_set_self'
[bfinject4realz] Calling dlopen() at 0x1829bb460...
[bfinject4realz] Returned from 'dlopen'
[bfinject4realz] Success! Library was loaded at 0x1c01786c0
[+] Injecting into '/var/containers/Bundle/Application/55C94FAA-A282-4FDC-967D-6A012D01087E/Reddit.app/Reddit'
[+] Getting Team ID from target application...
[+] Thinning dylib into non-fat arm64 image
[+] Signing injectable .dylib with Team ID 2TDUX39LX8 and platform entitlements...
[bfinject4realz] Calling task_for_pid() for PID 486.
[bfinject4realz] Calling thread_create() on PID 486
[bfinject4realz] Looking for ROP gadget... found at 0x1019a2ba0
[bfinject4realz] Fake stack frame at 0x10ab00000
[bfinject4realz] Calling _pthread_set_self() at 0x182bfb814...
[bfinject4realz] Returned from '_pthread_set_self'
[bfinject4realz] Calling dlopen() at 0x1829bb460...
[bfinject4realz] Returned from 'dlopen'
[bfinject4realz] Success! Library was loaded at 0x1c4179680
[+] So long and thanks for all the fish.
```

Once Cycript has been injected, you'll see the following message on your device:

<img src="https://i.imgur.com/OE8ruPv.png" width="400px"/>

You can connect to Cycript from your MacBook like this (assuming you installed Cycript into ~/bin/):

```
carl@calisto-3 /tmp $ ~/bin/cycript -r 192.168.1.33:1337
cy# UIApp
#"<RedditApplication: 0x102304a30>"
cy#
```

## How does it work?
At a high level, `bfinject4realz` side-loads a self-signed .dylib into a running Apple-signed App Store app.

The process is done in two stages.

### 1. Sign the dylib to be injected
Codesigning checks on iOS comprise userspace services (amfid) and kernel services (AppleMobileFileIntegrity). Both LiberiOS and Electra patch the userspace amfid process to bypass codesigning checks, but there are still further checks performed by the kernel.

However, Electra and LiberiOS are KPPless, which means they don't patch anything in the kernel; not a single byte. This is because of Kernel Patch Protection ("KPP"), an Apple security technology that does sophisticated kernel introspection to detect and thwart kernel patches. As a result, kernel codesigning checks are still intact.

Fortunately for us, it appears that the kernel assumes amfid has already checked the validity of the cryptographic signature attached to a dylib's entitlements. As a result, all we need to do is self-sign two entitlements into a dylib if we want the kernel to accept it:
* The first is the `platform-application` entitlement, which I believe indicates that the dylib is Apple software.
* The second is the Team ID of the signing certificate that was used to sign the code we are injecting into. For example, the Reddit app is signed by Team ID `2TDUX39LX8`. As a result, to inject a dylib into the Reddit app we must sign the dylib with the same Team ID: `2TDUX39LX8`.

bfinject takes care of all the signing shenanigans for you, which is nice.

### 2. Inject the correctly-signed dylib into the target process
* Using `task_for_pid()`, get a mach port for the target process
* Use the port to manipulate threads and non-executable memory segments in the target process
  * Note: without kernel patches, it is not possible to modify executable code in a process.
  * As a result, we have to use ROP tricks to execute code of our choice.
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
Note that on Electra, the version of `jtool` (@morpheus' code-signing multitool) doesn't support platform binary entitlements, so bfinject supplies `jtool` from LiberiOS and uses that instead. bfinject does not use Electra's `inject_criticald`.

## Credits
* Stefan Esser (10n1c) for the original ideas and code behind dumpdecrypted (https://github.com/stefanesser/dumpdecrypted/blob/master/dumpdecrypted.c)
* Dmitry Rodionov for lorgnette (https://github.com/rodionovd/liblorgnette/)
* Jonathan Levin for the  LiberiOS jailbreak (http://newosxbook.com/liberios/)
* Ian Beer for the async_wake exploit (https://bugs.chromium.org/p/project-zero/issues/detail?id=1417)
* Apple for a great mobile OS
