## OUT OF DATE --- READ THE SOURCE, NOT THE README


# dumpdecrypted
Decrypts iOS apps and corresponding frameworks on jailbroken 64bit iOS 9.x and 10.0.x - 10.2


## Use
* Copy `dumpdecrypted.dylib` to `/tmp` on your device
* Launch the target app
* Get a root shell on your device
* Find your app's PID using `ps`
* Type `cynject PID /tmp/dumpdecrypted.dylib`
* Check the console log for the device, it will tell you where the decrypted IPA is stored.

## Known issues
* 64bit only (I can port a 32bit version if needs be)
* If you're building it yourself instead of using the included `dumpdecrypted.dylib` then you must have an Apple Developer account to do the required code signing (at least for Yalu jailbroken 10.x devices)
