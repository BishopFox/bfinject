/*
    bfinject - Inject shared libraries into running App Store apps on iOS 11.x < 11.2
    https://github.com/BishopFox/bfinject

    Carl Livitt @ Bishop Fox
*/
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#import <UIKit/UIKit.h>
#include <sys/stat.h>
#include <pthread.h>
#include "lorgnette.h"
#include <stdio.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <mach/mach.h> 
#include <mach/exc.h>
#include <errno.h> 
#include <stdlib.h> 

#define STACK_SIZE ((1024 * 1024) * 512) // 512MB stack
#define ROP_ret "\xc0\x03\x5f\xd6"
#define ALIGNSIZE 8
#define align64(x) ( ((x) + ALIGNSIZE - 1) & ~(ALIGNSIZE - 1) )
#define UNINITIALIZED 0x11223344

static mach_port_t task = UNINITIALIZED;
static thread_act_port_array_t threadList = (thread_act_port_array_t)UNINITIALIZED;
static mach_msg_type_number_t threadCount = (mach_msg_type_number_t)UNINITIALIZED;
static thread_t thread = UNINITIALIZED;
static vm_address_t remoteStack = UNINITIALIZED;
static void *gadgetAddress = (void *)UNINITIALIZED;


static void *find_gadget(const char *gadget, int gadgetLen) {
    kern_return_t kr;
    vm_address_t addr;
    uint32_t depth = 1;
    vm_address_t address = 0;
    vm_size_t size = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

    while (1) {
      kr = vm_region_recurse_64(task, &address, &size, &depth, (vm_region_info_64_t)&info, &count);
      if(kr == KERN_INVALID_ADDRESS) {
        // Invalid address means we're done
        break;
      }
      if(kr != KERN_SUCCESS) {
          printf("[bfinject] ERROR: vm_region_recurse_64 returned !=  KERN_SUCCESS. This only works with App Store apps.\n");
          break;
      }

      if (info.is_submap) {
          depth++;
      }
      else {
        // if the segment is R-X, scan it for the gadget
        if(info.protection & VM_PROT_READ && info.protection & VM_PROT_EXECUTE) {
          // allocate local buffer for a copy of the identified memory segment
          char *buf = (char *)malloc((size_t)size);
          if(!buf) {
            printf("[bfinject] malloc fail\n");
            break;
          }
          
          // read the remote R-X pages into the local buffer
          kr = vm_read_overwrite(task, address, size, (vm_address_t)buf, &size);
          if(kr != KERN_SUCCESS) {
            printf("[bfinject] vm_read_overwrite fail\n");
            break;
          }
          
          // grep for the gadget
          char *ptr = (char *)memmem((const void *)buf, (size_t)size, (const void *)gadget, (size_t)gadgetLen);
          free(buf);
          
          // Make sure the gadget is aligned correctly
          if(ptr) {
            vm_size_t offset = (vm_size_t)(ptr - buf);
            vm_address_t gadgetAddrReal = address + offset;
            printf("             gadget candidate: 0x%llx ... ", (uint64_t)gadgetAddrReal);fflush(stdout);
            if(((uint64_t)gadgetAddrReal % 8) == 0) {
              printf("Found @ 0x%lx\n", gadgetAddrReal);
              return (void *)gadgetAddrReal;
            }
            else {
              printf("unaligned, skipping\n");
            }
          }
        }
      }
      address += size;
    }

    return NULL; // gadget not found in an executable text segment
}


static void get_task(int pid) {
  // Get port for target app's process
  if(task == UNINITIALIZED) {
    int kret = task_for_pid(mach_task_self(), pid, &task);
    if(kret != KERN_SUCCESS) {
      printf("[bfinject] task_for_pid() failed with message %s!\n",mach_error_string(kret));
    }
  }
}


extern uint64_t ropcall(int pid, const char *symbol, const char *symbolLib, const char *argMap, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4) {
  kern_return_t kret;
  arm_thread_state64_t state = {0};
  mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;

  // Find the address of the function to be called in the remote process
  printf("[bfinject] Looking for '%s' in the target process...\n", symbol);
  uint64_t targetFunctionAddress = lorgnette_lookup_image(task, symbol, symbolLib);  
  if(!targetFunctionAddress) {
    printf("[bfinject] Could not find a symbol called '%s'\n", symbol);
    return 0;
  }
  printf("[bfinject] Desired function '%s' is at %p\n", symbol, (void *)targetFunctionAddress);
  
  // Setup a new registers for the call to target function
  printf("[bfinject] Setting registers with destination function\n");
  state.__pc = (uint64_t)targetFunctionAddress; // We'll be jumping to here
  state.__lr = (uint64_t)gadgetAddress;         // Address of the infinite loop RET gadget
  state.__sp = (uint64_t)(remoteStack + STACK_SIZE) - (STACK_SIZE / 4);  // Put $sp bang in the middle of the fake stack frame
  state.__fp = state.__sp;


  // Allocate a STACK_SIZE local buffer that we'll populate before copying it to the remote process
  char *localFakeStack = (char *)malloc((size_t)STACK_SIZE);

  // Ok, now we handle the parameters being passed
  char *argp = (char *)argMap;
  char *stackPtr = localFakeStack;
  uint64_t paramLen = 0;

  for(int param = 0; param <= 4; param++) {
    if(!(*argp))
      break;

    switch(*argp) {
      case 's': // char * string
        int numDigits;
        char tmpBuf[6];

        argp++;
        numDigits = 0;
        while(*argp >= '0' && *argp <= '9') {
          if(++numDigits == 6) {
            printf("[bfinject] String too long, param=%d\n", param);
            return 0;
          }
          tmpBuf[numDigits-1] = *(argp++);
        }
        tmpBuf[numDigits] = 0;

        paramLen = strtoull(tmpBuf, NULL, 10);
        
        uint64_t *argPtr;
        if(param==0)
          argPtr = arg1;
        if(param==1)
          argPtr = arg2;
        if(param==2)
          argPtr = arg3;
        if(param==3)
          argPtr = arg4;
        
        memcpy(stackPtr, argPtr, paramLen);

        state.__x[param] = (uint64_t)remoteStack + (stackPtr - localFakeStack);
        stackPtr += 16;
        stackPtr += paramLen;
        stackPtr = (char *)align64((uint64_t)stackPtr);

        break;

      case 'u': // uint64_t
        state.__x[param] = (param==0)?(uint64_t)arg1:(param==1)?(uint64_t)arg2:(param==2)?(uint64_t)arg3:(uint64_t)arg4;
        argp++;
        break;

      default:
        printf("[bfinject] Uknown argument type: '%c'\n", *argp);
        return 0;
    }
  }

  printf("[bfinject] New CPU state:\n             $pc = 0x%llx\n             $sp = 0x%llx\n             \
$x0 = 0x%llx\n             $x1 = 0x%llx\n             $x2 = 0x%llx\n             $x3 = 0x%llx\n", 
state.__pc, state.__sp, state.__x[0], state.__x[1], state.__x[2], state.__x[3]);

  // Copy fake stack buffer over to the new stack frame in the remote process
  kret = vm_write(task, remoteStack, (vm_address_t)localFakeStack, STACK_SIZE);
  
  if(kret != KERN_SUCCESS) {
    printf("[bfinject] Unable to copy fake stack to target process. Error: %s\n", mach_error_string(kret));
    return 0;
  }
  
  // start the remote thread with the fake stack and tweaked registers
  printf("[bfinject] Resuming thread with hijacked regs\n");
  thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
  thread_resume(thread);

  // Wait for the remote thread to RET to the infinite loop gadget...
  printf("[bfinject] Waiting for thread to hit the infinite loop gadget...\n");
  while(1) {
    usleep(250000);
    thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount);

    // are we in the infinite loop gadget yet?
    if(state.__pc == (uint64_t)gadgetAddress) {
      printf("[bfinject] We hit the infinite loop, call complete. Restoring stack and registers.\n");
      
      // dlopen is done and we're stuck in our RET loop. restore the universe.
      thread_suspend(thread);

      // so long and thanks for all the fish
      break;
    }
  }

  // return value is in x0  
  return (uint64_t)state.__x[0];
}


char *readmem(uint64_t addr, vm_size_t *len) {
  static char buf[16384];

  memset(buf, 0, 16384);
  vm_read_overwrite(task, addr, 16383, (vm_address_t)buf, len);
  
  return buf;
}


int main(int argc, char ** argv)
{
  char argMap[128];
  char *pathToAppBinary;
  int pid;
  uint64_t retval;
  kern_return_t kret;

  if(argc == 3) {
    pid = atoi(argv[1]);
    pathToAppBinary = argv[2];
  } else {
    printf("bfinject -=[ https://www.bishopfox.com ]=-\nSyntax: %s <pid> <path/to/dylib>\n", argv[0]);
    exit(1);
  }

  printf("[bfinject] Getting tfp.\n");
  get_task(pid);
  
  printf("[bfinject] Creating new remote thread\n");
  if((kret = thread_create(task, &thread)) != KERN_SUCCESS) {
    printf("[bfinject] Failed to create thread in remote process. Is it really an App Store app?\n");
    printf("[bfinject] thread_create() returned %d\n[bfinject] errno = %d = %s\n", kret, errno, strerror(errno));
    exit(1);
  }
  printf("[bfinject] Thread ID: %u (0x%x)\n", thread, thread);

  // Find an infinite loop ROP gadget in the remote process
  printf("[bfinject] Looking for RET gadget in the target app...\n");
  if(!((gadgetAddress = (void *)(uint64_t)find_gadget(ROP_ret, 4)))) {
    printf("[bfinject] Infinite loop RET gadget not found :(\n");
    return 0;
  }

  // Create a new memory section in the remote process. Mark it RW like a stack should be.
  kret = vm_allocate(task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
  if (kret != KERN_SUCCESS) {
    printf("[bfinject] Unable to create a new stack in the remote process. Error: %s\n", mach_error_string(kret));
    return 0;
  }
  kret = vm_protect(task, remoteStack, STACK_SIZE, FALSE, VM_PROT_WRITE|VM_PROT_READ);
  if(kret != KERN_SUCCESS) {
    printf("[bfinject] Unable to vm_protect(VM_PROT_WRITE|VM_PROT_READ) the new stack. Error: %s\n", mach_error_string(kret));
    return 0;
  }
  printf("[bfinject] Fake stack frame is %d bytes at %p in remote proc\n", STACK_SIZE, (void *)remoteStack);

  // Call _pthread_set_self(NULL) to avoid crashing in dlopen() later
  ropcall(pid, "_pthread_set_self", "libsystem_pthread.dylib", (char *)"u", 0, 0, 0, 0);
  
  // Call dlopen() to load the requested shared library
  snprintf(argMap, 127, "s%luu", strlen(pathToAppBinary));
  retval = ropcall(pid, "dlopen", "libdyld.dylib", argMap, (uint64_t *)pathToAppBinary, (uint64_t *)(uint64_t )(RTLD_NOW|RTLD_GLOBAL), 0, 0);
  printf("[bfinject] dlopen() returned 0x%llx (%s)\n", (uint64_t)retval, (retval==0)?"FAILURE":"success");
  if(retval == 0) {
    // Call dlerror() to see what went wrong
    retval = ropcall(pid, "dlerror", "libdyld.dylib", "", 0, 0, 0, 0);
    vm_size_t bytesRead;
    char *buf = readmem(retval, &bytesRead);
    printf("[bfdecrypt] dlerror() returned: %s\n", buf);
  }

  // Clean up the mess
  thread_terminate(thread);
  vm_deallocate(task, remoteStack, STACK_SIZE);

  exit(0);
}