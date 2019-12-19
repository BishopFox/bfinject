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
#include <mach-o/dyld_images.h>
#include <mach-o/dyld.h>

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
static uint64_t dlopenAddress = 0;

static void get_task(int pid);
static char *readmem(uint64_t addr, vm_size_t *len);
static void *find_gadget(const char *gadget, int gadgetLen);
static uint64_t ropcall_by_symboll(const char *symbol, const char *symbolLib, const char *argMap, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4);
static uint64_t ropcall_by_address(uint64_t address,  const char *symbol, const char *argMap, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4);
vm_address_t find_mem(vm_address_t startAddress, vm_size_t lenToSearch, const char *sequence, int seqLen);
vm_address_t find_opcode(vm_address_t startAddress, vm_size_t lenToSearch, uint32_t opcodeMask, uint32_t opcodeMaskValue);


/*
  Entry point
*/
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

  printf("[bfinject4realz] Calling task_for_pid() for PID %d.\n", pid);
  get_task(pid);
  
  printf("[bfinject4realz] Calling thread_create() on PID %d\n", pid);
  if((kret = thread_create(task, &thread)) != KERN_SUCCESS) {
    printf("[bfinject4realz] ERROR: thread_create() returned %d\n\n", kret);
    printf("[bfinject4realz] Failed to create thread in remote process.\n                 This most likely is caused by \"Tweaks\" being enabled in Electra.\n                 Please try rebooting and re-jailbreaking with \"Tweaks\" disabled.\n");
    exit(1);
  }

  // Find an infinite loop ROP gadget in the remote process
  printf("[bfinject4realz] Looking for ROP gadget... ");fflush(stdout);
  if(!((gadgetAddress = (void *)(uint64_t)find_gadget(ROP_ret, 4)))) {
    printf("[bfinject4realz] WAT: Infinite loop RET gadget not found :(\n");
    return 0;
  }
  printf("found at 0x%llx\n", (uint64_t)gadgetAddress);

  // Create a new memory section in the remote process. Mark it RW like a stack should be.
  kret = vm_allocate(task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
  if (kret != KERN_SUCCESS) {
    printf("[bfinject4realz] ERROR: Unable to vm_allocate() a new stack in the remote process.\n");
    printf("[bfinject4realz] The error was: %s\n", mach_error_string(kret));
    return 0;
  }
  kret = vm_protect(task, remoteStack, STACK_SIZE, FALSE, VM_PROT_WRITE|VM_PROT_READ);
  if(kret != KERN_SUCCESS) {
    printf("[bfinject4realz] ERROR: Unable to vm_protect(VM_PROT_WRITE|VM_PROT_READ) the new stack.\n");
    printf("[bfinject4realz] The error was: %s\n", mach_error_string(kret));
    return 0;
  }
  printf("[bfinject4realz] Fake stack frame at %p\n", (void *)remoteStack);

  // Get dyld version. We have the same dyld as the target
  uint64_t dyld_version = NSVersionOfRunTimeLibrary("libdyld.dylib");

  // Call _pthread_set_self(NULL) to avoid crashing in dlopen() later
  // Handle new dyld versions differently, becuase their exported function won't get NULL as an argument
  if (dyld_version >= 0x2d70000) {
    // Get dyld address in remote task
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    struct task_dyld_info info;
    kern_return_t ret = task_info(task, TASK_DYLD_INFO, (task_info_t) &info, &count);
    if (ret) {
        printf("task_info returned %d. Aborting\n", ret);
        return 1;
    }

    vm_size_t size_to_read = sizeof(dyld_all_image_infos);
    struct dyld_all_image_infos *all_image_infos_local = (struct dyld_all_image_infos *)readmem(info.all_image_info_addr, &size_to_read);
    vm_address_t dyld_address = (vm_address_t)all_image_infos_local->dyldImageLoadAddress;
    free(all_image_infos_local);

    // Find _pthread_set_self_dyld function by a unique byte sequence it has
    const char *pthread_set_self_bytes = "\x00\x01\x67\x9e\x09\xb1\x02\x91\x20\x1d\x18\x4e\x00\x39\x80\x3d";
    vm_address_t bytes_address = find_mem(dyld_address, 0x100000, pthread_set_self_bytes, 16);
    if (!bytes_address) {
      printf("Cant find _pthread_set_self_dyld function. Aborting\n");
      return 1;
    }
    
    // Find the beginning of the function, by searching the STP opcode
    vm_address_t _pthread_set_self_address = find_opcode(bytes_address, 0x100, 0xffc00000, 0xa9800000);
    if (!_pthread_set_self_address) {
      printf("Cant find _pthread_set_self_dyld function. Aborting..\n");
      return 1;
    }

    ropcall_by_address(_pthread_set_self_address, "_pthread_set_self_dyld", "", 0, 0, 0, 0);
  } else {
    // Old dyld
    ropcall_by_symboll("_pthread_set_self", "libsystem_pthread.dylib", (char *)"u", 0, 0, 0, 0);
  }

  // Call dlopen() to load the requested shared library
  snprintf(argMap, 127, "s%luu", strlen(pathToAppBinary));
  if((retval = ropcall_by_symboll("dlopen", "libdyld.dylib", argMap, (uint64_t *)pathToAppBinary, (uint64_t *)(uint64_t )(RTLD_NOW|RTLD_GLOBAL), 0, 0)) == 0) {
    // If dlopen() failed, we call dlerror() to see what went wrong
    printf("[bfinject4realz] ERROR: dlopen() failed to load the dylib.returned 0x%llx (%s)\n", (uint64_t)retval, (retval==0)?"FAILURE":"success!");
    
    retval = ropcall_by_symboll("dlerror", "libdyld.dylib", "", 0, 0, 0, 0);
    
    vm_size_t bytesRead = 4096;
    char *buf = readmem(retval, &bytesRead);
    printf("[bfinject4realz] dlerror() returned: %s\n", buf);
    free(buf);
  } else {
    printf("[bfinject4realz] Success! Library was loaded at 0x%llx\n", (uint64_t)retval);
    /*
    // if we're decrypting, try to get the path to the saved IPA file as a user convenience
    uint64_t decryptedIPAPathAddress = lorgnette_lookup_image(task, "decryptedIPAPath", "bfdecrypt.dylib");
    if(decryptedIPAPathAddress) {
      uint64_t pathLenAddress = lorgnette_lookup_image(task, "pathLen", "bfdecrypt.dylib");
      vm_size_t readLen = 8;
      uint64_t *pathLen = (uint64_t *)readmem(pathLenAddress, &readLen);
      readLen = (vm_size_t)*pathLen;
      char *decryptedIPAPath = readmem(decryptedIPAPathAddress, &readLen);
      printf("[bfinject4realz] In a few seconds the IPA will be saved to '%s'\n", decryptedIPAPath);
      free(pathLen);
      free(decryptedIPAPath);
    }
    */
  }

  // Clean up the mess
  thread_terminate(thread);
  vm_deallocate(task, remoteStack, STACK_SIZE);

  exit(0);
}


/*
  find_gadget traverses each of the remote process' pages marked R-X looking for
  the specified ROP gadget.
*/
static void *find_gadget(const char *gadget, int gadgetLen) {
    kern_return_t kr;
    vm_size_t size = 0;
    uint64_t targetAddress = 0;
    
    if(dlopenAddress == 0) {
      dlopenAddress = lorgnette_lookup_image(task, "dlopen", "libdyld.dylib");
      if(!dlopenAddress) {
        printf("[bfinject4realz] ERROR: Could not find a symbol called 'dlopen'\n");
        return 0;
      }
    }
    targetAddress = dlopenAddress;
    size = 65536;

    int offset = 0;
    while (size > 0) {
      vm_address_t gadgetAddr = find_mem(targetAddress + offset, size, gadget, gadgetLen);
      if (((uint64_t)gadgetAddr % 8) == 0) {
        return (void *)gadgetAddr;
      } else {
        // The gadget we found isn't 64-bit aligned, so we can't use it. Keep trying.        
        offset = gadgetAddr - targetAddress;
        offset += gadgetLen;
        size -= offset;
      }
    }

    return NULL;
}

/*
  find_mem searches for a sequence of bytes in a specified memory area
*/
vm_address_t find_mem(vm_address_t startAddress, vm_size_t lenToSearch, const char *sequence, int seqLen)
{
  vm_size_t size = lenToSearch;
  const char *buf = readmem(startAddress, &size);
  if (!buf || (size != lenToSearch)) {
    printf("[bfinject4realz] ERROR: Can't read %lu bytes from address %p\n", lenToSearch, buf);
    if (buf) {
      free((void*)buf);
    }
    return 0;
  }

  char *seqInBuf = (char *)memmem((const void *)buf, size, (const void *)sequence, (size_t)seqLen);
  if (!seqInBuf) {
    printf("[bfinject4realz] ERROR: Can't find bytes in memory\n");
    free((void*)buf);
    return 0;
  }
  vm_size_t offset = (vm_size_t)(seqInBuf - buf);
  free((void*)buf);

  return (vm_address_t)startAddress + offset;
}


/*
  Search backwards from the given address, and find the requested opcode
*/
vm_address_t find_opcode(vm_address_t startAddress, vm_size_t lenToSearch, uint32_t opcodeMask, uint32_t opcodeMaskValue)
{
  vm_size_t size = lenToSearch;
  
  // Align the searching len to opcode size
  if (lenToSearch % 4 != 0) {
    lenToSearch &= ~3;
  }

  // Read the bytes before the requested address
  const char *buf = readmem(startAddress - size, &size);
  if (!buf || (size != lenToSearch)) {
    printf("[bfinject4realz] ERROR: Can't read %lu bytes from address %p\n", lenToSearch, buf);
    if (buf) {
      free((void*)buf);
    }
    return 0;
  }

  // Search backwards for the opcode
  for (unsigned long i = 4; i <= lenToSearch; i += 4) {
    uint32_t opcode = *(uint32_t*)(&buf[size - i]);
    if ((opcode & opcodeMask) == opcodeMaskValue) {
      free((void*)buf);
      return startAddress - i;
    }
  }
  
  free((void*)buf);
  return 0;
}


static void get_task(int pid) {
  // Get port for target app's process
  if(task == UNINITIALIZED) {
    int kret = task_for_pid(mach_task_self(), pid, &task);
    if(kret != KERN_SUCCESS) {
      printf("[bfinject4realz] ERROR: task_for_pid() failed with message %s!\n",mach_error_string(kret));
      exit(1);
    }
  }
}


/*
  Call any loaded function in the remote process.
  We use it to call _pthread_set_self(), dlopen() and, if needed, dlerror().
  Supports up to 4 parameters, but should really use varargs.
*/
static uint64_t ropcall_by_symboll(const char *symbol, const char *symbolLib, const char *argMap, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4) {
  uint64_t targetFunctionAddress = 0;

  // Find the address of the function to be called in the remote process
  //printf("[bfinject4realz] Looking for '%s' in the target process...\n", symbol);
  if(strcmp(symbol, "dlopen") == 0) {
    if(dlopenAddress == 0) {
      dlopenAddress = lorgnette_lookup_image(task, "dlopen", "libdyld.dylib");
      if(!dlopenAddress) {
        printf("[bfinject4realz] ERROR: Could not find a symbol called '%s'\n", symbol);
        return 0;
      }
    }
    targetFunctionAddress = dlopenAddress;
  } else {
    targetFunctionAddress = lorgnette_lookup_image(task, symbol, symbolLib);
  }

  return ropcall_by_address(targetFunctionAddress, symbol, argMap, arg1, arg2, arg3, arg4);
}

/*
  Called by ropcall_by_symboll. 
  Used also when we call a function using it's address directly instead of it's symbol.
*/
static uint64_t ropcall_by_address(uint64_t targetFunctionAddress, const char *symbol, const char *argMap, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4) {

  kern_return_t kret;
  arm_thread_state64_t state = {0};
  mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;

  // Setup a new registers for the call to target function
  //printf("[bfinject4realz] Setting CPU registers with function and ROP addresses\n");
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
            printf("[bfinject4realz] ERROR: String too long, param=%d\n", param);
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
        printf("[bfinject4realz] ERROR: Uknown argument type: '%c'\n", *argp);
        return 0;
    }
  }

  // Copy fake stack buffer over to the new stack frame in the remote process
  kret = vm_write(task, remoteStack, (vm_address_t)localFakeStack, STACK_SIZE);
  free(localFakeStack);
  
  if(kret != KERN_SUCCESS) {
    printf("[bfinject4realz] ERROR: Unable to copy fake stack to target process. Error: %s\n", mach_error_string(kret));
    return 0;
  }
  
  // start the remote thread with the fake stack and tweaked registers
  printf("[bfinject4realz] Calling %s() at %p...\n", symbol, (void *)targetFunctionAddress);
  thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
  thread_resume(thread);

  // Wait for the remote thread to RET to the infinite loop gadget...
  while(1) {
    usleep(250000);
    thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount);

    // are we in the infinite loop gadget yet?
    if(state.__pc == (uint64_t)gadgetAddress) {
      printf("[bfinject4realz] Returned from '%s'\n", symbol);
      
      // dlopen is done and we're stuck in our RET loop. restore the universe.
      thread_suspend(thread);

      // so long and thanks for all the fish
      break;
    }
  }

  // return value is in x0  
  return (uint64_t)state.__x[0];
}

// Caller must free() the pointer returned by readmem()
static char *readmem(uint64_t addr, vm_size_t *len) {
  char *buf = (char *)malloc((size_t)*len);
  if(buf)
    vm_read_overwrite(task, addr, *len, (vm_address_t)buf, len);
  return buf;
}