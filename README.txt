It is essential that you move bfdecrypt.dylib into a new directory.
SHIT WILL NOT WORK if you don't do this.

mkdir /System/Library/Frameworks/bfdecrypt.framework/ 
mv bfdecrypt.dylib /System/Library/Frameworks/bfdecrypt.framework/

Then run:

bash /jb/usr/bin/bfinject PID /System/Library/Frameworks/bfdecrypt.framework/bfdecfypt.dylib
