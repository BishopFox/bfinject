/*
    BF Decryptor - Decrypt iOS apps and repack them into an .ipa
    https://github.com/BishopFox/bfinject

    Carl Livitt @ Bishop Fox
*/
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#import <UIKit/UIKit.h>
#include <sys/stat.h>
#include <pthread.h>
#include "DumpDecrypted.h"
#include "lorgnette.h"
#include <stdio.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <mach/mach.h> 
#include <mach/exc.h>
#include <errno.h> 
#include <stdlib.h> 

const char *fullPathStr;

__attribute__((constructor)) void rocknroll() {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        fullPathStr = _dyld_get_image_name(0);

        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt] Full path to app: %s", fullPathStr);
        DumpDecrypted *dd = [[DumpDecrypted alloc] initWithPathToBinary:[NSString stringWithUTF8String:fullPathStr]];
        [dd createIPAFile];

        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt]");
        NSLog(@"[bfdecrypt] Over and out.");
    });
}