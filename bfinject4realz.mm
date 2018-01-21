/*
  ROP style: find gadget to call dlopen, etc
    pthread suspend
    pthread save all regs
    allocate some space for a new "stack"
    place string "/path/to/lib" at known location in stack
    pthread set 
      x8 = <addr of dlopen>
      sp = new data segment "stack"
      x0 = <addr of string "/path/to/dylib" in new segment>
      x1 = RTLD_DEFAULT | RTLD_GLOBAL
      lr = ROP gadget to infinite loop at known addresses
      pc = ROP gadget to do br x8
    pthread poll for $pc == known ROP gadget loop (br x8!!)
    restore regs
    resume execution
*/

/*
rm dumpdecrypted; wget http://192.168.1.16:8000/dumpdecrypted; chmod +x dumpdecrypted ; jtool --sign platform --ent entitlements.xml --inplace dumpdecrypted;dumpdecrypted
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
#include "DumpDecrypted.h"
#include "lorgnette.h"
#include <stdio.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <mach/mach.h> 
#include <mach/exc.h>
#include <errno.h> 
#include <stdlib.h> 

#define STACK_SIZE 128000
#define ROP_blr_x8 "\x00\x01\x3f\xd6"
#define ROP_br_x8 "\x00\x01\x1f\xd6"
#define ROP_add_ret "\x91\xc0\x03\x5f\xd6"
#define ROP_ret "\xc0\x03\x5f\xd6"
//#define DYLIB_PATH "////////////////System/Library/Frameworks/simple.framework/simple.dylib"
//#define DYLIB_PATH "////////////////var/mobile/Containers/Data/Application/AA1D4A5D-DBA3-4C76-B41C-C837987AFD6B/Documents/simple.dylib"
//#define DYLIB_PATH "////////////////etc/shadow"
#define ALIGNSIZE 8
#define align64(x) ( ((x) + ALIGNSIZE - 1) & ~(ALIGNSIZE - 1) )
#define ERR 0x00abcdef
#define UNINITIALIZED 0x11223344

static mach_port_t task = UNINITIALIZED;
static thread_act_port_array_t threadList = (thread_act_port_array_t)UNINITIALIZED;
static mach_msg_type_number_t threadCount = (mach_msg_type_number_t)UNINITIALIZED;

// From xnu-2782.1.97/bsd/uxkern/ux_exception.c
typedef struct {
    mach_msg_header_t Head;
    /* start of the kernel processed data */
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    /* end of the kernel processed data */
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    mach_exception_data_t code;
    /* some times RCV_TO_LARGE probs */
    char pad[512];
} exc_msg_t;

static void resume_all_threads() {
  printf("resume_all_threads: found %llu threads, resuming them all.\n", (unsigned long long)threadCount);
  for(int i = 0; i < threadCount; i++) {
    thread_resume(threadList[i]);
    usleep(10000); // needed?
  }
  
  return;
}

static thread_t get_injectable_thread() {
  kern_return_t kret;

  if(threadList == (thread_act_port_array_t)UNINITIALIZED) {
    kret = task_threads(task, &threadList, &threadCount);
    if (kret!=KERN_SUCCESS) {
      printf("get_injectable_thread: task_threads() failed with message %s!\n", mach_error_string(kret));
    }
  } 
  
  if(threadCount <= 1) {
    printf("get_injectable_thread: not enough threads\n");
    return (thread_t)NULL;
  }

  printf("get_injectable_thread: found %llu threads, suspending them all.\n", (unsigned long long)threadCount);
  for(int i = 0; i < threadCount; i++) {
    thread_suspend(threadList[i]);
    thread_abort_safely(threadList[i]);
  }

  return threadList[0];
}

static void *find_gadget(const char *gadget, int gadgetLen) {
    mach_msg_type_number_t info_count;
    kern_return_t kr;
    arm_thread_state64_t state;
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
          printf("vm_region_recurse_64 returned !=  KERN_SUCCESS\n");
          continue;
      }

      //printf("c = %llu\na = 0x%x\ns = %llu\n", count, address, size);

      if (info.is_submap) {
          depth++;
      }
      else {
        // if the segment is R-X, scan it for the gadget
        if(info.protection & VM_PROT_READ && info.protection & VM_PROT_EXECUTE) {
          // allocate space for the copy of the identified memory segment
          char *buf = (char *)malloc((size_t)size);
          if(!buf) {
            printf("malloc fail\n");
            break;
          }
          
          // read the R-X segment into a local buffer
          kr = vm_read_overwrite(task, address, size, (vm_address_t)buf, &size);
          if(kr != KERN_SUCCESS) {
            printf("vm_read_overwrite fail\n");
            break;
          }
          
          char *ptr = (char *)memmem((const void *)buf, (size_t)size, (const void *)gadget, (size_t)gadgetLen);
          free(buf);
          if(ptr) {
            vm_size_t offset = (vm_size_t)(ptr - buf);
            vm_address_t gadgetAddr = address + offset;
            printf("gadget candidate: 0x%llx ... ", (uint64_t)gadgetAddr);fflush(stdout);
            if(((uint64_t)gadgetAddr % 16) == 0 && (gadgetAddr & 0x3) == 0) {
              printf("\n");
              return (void *)gadgetAddr;
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

// handles E_BAD_ACCESS thrown in remote thread
static boolean_t my_exc_server(mach_msg_header_t *request, mach_msg_header_t *reply) {
  printf("Inside exc_server\n");
  return false;
}

static kern_return_t catch_exception(mach_port_t exception_port) {
	kern_return_t err = mach_msg_server_once(my_exc_server, sizeof(exc_msg_t), exception_port, 0);
  return err;
}

static void get_task(int pid) {
  // Get port for target app's process
  if(task == UNINITIALIZED) {
    int kret = task_for_pid(mach_task_self(), pid, &task);
    if(kret!=KERN_SUCCESS) {
      printf("task_for_pid() failed with message %s!\n",mach_error_string(kret));
    }
  }
}

char *readmem(uint64_t addr, vm_size_t *len) {
  static char buf[16384];

  memset(buf, 0, 16384);
  vm_read_overwrite(task, addr, 16383, (vm_address_t)buf, len);
  
  return buf;
}

uint64_t ropcall(int pid, const char *symbol, char *argMap, uint64_t *arg1, uint64_t *arg2, uint64_t *arg3, uint64_t *arg4) {
  kern_return_t kret;
  arm_thread_state64_t state = {0}, savedState = {0};
  kern_return_t err;
  static thread_t thread = UNINITIALIZED;
  mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;
  
  // task_for_pid() for remote process
  get_task(pid);
  
  // Find our infinite loop ROP gadget in the remote process
  void *gadgetAddress = (void *)(uint64_t)find_gadget(ROP_ret, 4);
  if(!gadgetAddress) {
    printf("Infinite loop RET gadget not found :(\n");
    return 0;
  } else {
    printf("Infinite loop RET gadget found @ %p\n", gadgetAddress);
  }

  // Create a new memory section in the remote process. Mark it RW like a stack should be.
	static vm_address_t stack = UNINITIALIZED;
  if(stack == UNINITIALIZED) {
    kret = vm_allocate(task, &stack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kret != KERN_SUCCESS) {
      printf("Unable to create a new stack in the remote process. Error: %s\n", mach_error_string(kret));
      return 0;
    }
    kret = vm_protect(task, stack, STACK_SIZE, FALSE, VM_PROT_WRITE|VM_PROT_READ);
    if(kret != KERN_SUCCESS) {
      fprintf(stderr,"Unable to vm_protect the new stack as RW. Error: %s\n", mach_error_string(kret));
      return 0;
    }
  }
  printf("Fake stack frame is %d bytes at %p in remote proc\n", STACK_SIZE, (void *)stack);

  // Get the thread that we'll be using as our ROP host.
  // This process suspends ALL threads in the target app and returns the first non-main UI thread.
  if((thread = get_injectable_thread()) == (thread_t)NULL) {
    printf("No threads we can inject into?!?\n");
    return 0;
  }

  printf("Sleeping...\n");
  sleep(1); // just settle...
  printf("Back!\n");

  // Save current state
  kret = thread_get_state( thread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount);
  if (kret!=KERN_SUCCESS) {
    printf("get_thread_state: thread_get_state() failed with message %s!\n", mach_error_string(kret));
    return 0;
  }
  memcpy((void *)&savedState, (void *)&state, sizeof(arm_thread_state64_t));
  printf("Saved state:\n$pc = 0x%llx\n$sp = 0x%llx\n$x0 = 0x%llx\n", savedState.__pc, savedState.__sp, savedState.__x[0]);
  
  // Find the address of the function to be called in the remote process
  uint64_t targetFunctionAddress = lorgnette_lookup_image(task, symbol, NULL);
  if(!targetFunctionAddress) {
    printf("Could not find a symbol called '%s'\n", symbol);
    return 0;
  }
  printf("Desired function '%s' is at %p\n", symbol, (void *)targetFunctionAddress);
  
  // Setup a new registers for the call to target function
  printf("Setting registers with destination function\n");
  state.__pc = (uint64_t)targetFunctionAddress; // We'll be jumping to here
  state.__lr = (uint64_t)gadgetAddress;         // Address of the infinite loop RET gadget
  state.__sp = (uint64_t)stack + (STACK_SIZE / 2);  // Put $sp bang in the middle of the fake stack frame
  state.__fp = (uint64_t)stack + (STACK_SIZE / 4);  // $fp, too. Put it quarter way.

  // Allocate a STACK_SIZE local buffer that we'll populate before copying to the remote process
  char *fakeStack = (char *)malloc((size_t)STACK_SIZE);

  // Ok, now we handle the parameters being passed
  char *argp = argMap;
  char *stackPtr = fakeStack;
  uint64_t paramLen = 0;

  for(int param = 0; param <= 4; param++) {
    if(!(*argp))
      break;

    switch(*argp) {
      case 's': // char * string
        int numDigits;
        char tmpBuf[6];

        printf("Processing 's' argument\n");
        argp++;
        numDigits = 0;
        while(*argp >= '0' && *argp <= '9') {
          if(++numDigits == 6) {
            printf("String too long, param=%d\n", param);
            return 0;
          }
          tmpBuf[numDigits-1] = *(argp++);
        }
        tmpBuf[numDigits] = 0;

        paramLen = strtoull(tmpBuf, NULL, 10);
        //printf("Length of 's' argument: %llu\n", paramLen);
        
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
        printf("s: %s\n", (char *)argPtr);

        state.__x[param] = (uint64_t)stack + (stackPtr - fakeStack);
        printf("x%d: 0x%llx\n ('%s')\n", param, state.__x[param], (char *)argPtr);
        stackPtr += 16;
        stackPtr += paramLen;
        stackPtr = (char *)align64((uint64_t)stackPtr);

        break;

      case 'u': // uint64_t
        state.__x[param] = (param==0)?(uint64_t)arg1:(param==1)?(uint64_t)arg2:(param==2)?(uint64_t)arg3:(uint64_t)arg4;
        argp++;
        break;

      default:
        printf("Uknown argument type: '%c'\n", *argp);
        return 0;
    }
  }

  // Copy fake stack buffer over to the new stack frame in the remote process
  kret = vm_write(task, stack, (vm_address_t)fakeStack, STACK_SIZE);
  if(kret != KERN_SUCCESS) {
    fprintf(stderr, "Unable to copy fake stack to target. Error: %s\n", mach_error_string(kret));
    return 0;
  }
  
  // start the remote thread again, but with the fake stack and tweaked registers
  printf("Resuming thread with hijacked regs\n");
  thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
  thread_resume(thread);

  // Wait for the remote thread to RET to the infinite loop gadget...
  printf("Waiting for thread to hit the infinite loop gadget...\n");
  uint64_t oldPc=0xaaaaaaaa, oldLr=0xbbbbbbbb, oldSp=0xcccccccc; 
  while(1) {
    usleep(500000);
    thread_suspend(thread);
    thread_abort_safely(thread);

    thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount);
    if(state.__pc != oldPc || state.__lr != oldLr || state.__sp != oldSp) {
      oldPc = state.__pc;
      oldLr = state.__lr;
      oldSp = state.__sp;
      printf("pc: 0x%llx\nlr: 0x%llx\nsp: 0x%llx\n\n", state.__pc, state.__lr, state.__sp);
    }
    
    /*

    // wait a sec
    sleep(1);

    // make thread safe
    thread_suspend(thread);
    thread_abort_safely(thread);
    
    // grab the regs
    thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount);
    */
    // are we in the infinite loop gadget yet?
    if(state.__pc == (uint64_t)gadgetAddress) {
      printf("\nWe hit the infinite loop, call complete. Restoring stack and registers.\n");
      // dlopen is done and we're looping. restore the universe.
      thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&savedState, ARM_THREAD_STATE64_COUNT);
      
      // resume all the threads. these are not the droids you are looking for.
      resume_all_threads();

      // so long and thanks for all the fish
      break;
    }

    // keep trying
    thread_resume(thread);
  }

  // we even get the return value :)
  printf("And we're done. x0 = 0x%llx\n", state.__x[0]);

  return (uint64_t)state.__x[0];
}


/*
 * main()
 */
int main(int argc, char ** argv)
{
  char argMap[128];
  char *pathToAppBinary;
  char cmd[16384];
  int pid;
  uint64_t retval;

  if(argc == 3) {
    pid = atoi(argv[1]);
    pathToAppBinary = (char *)malloc((size_t)strlen(argv[2]) + 17);
    snprintf(pathToAppBinary, strlen(argv[2]) + 16, "///////////////%s", argv[2]);
  } else {
    printf("bfinject v0.1 -=[ https://www.bishopfox.com ]=-\nSyntax: %s <pid> <path/to/dylib>\n", argv[0]);
    exit(1);
  }

  // Call dlopen() to try and load unsigned code
  printf("[bfinject] Injecting %s into PID %d...\n", strrchr(pathToAppBinary, '/')+1, pid);
  snprintf(argMap, 127, "s%luu", strlen(pathToAppBinary));
  retval = ropcall(pid, "dlopen", argMap, (uint64_t *)pathToAppBinary, (uint64_t *)((uint64_t )RTLD_LAZY), 0, 0);
  printf("[bfinject] dlopen() returned 0x%llx\n", retval);

  /*
  usleep(5000);

  // Call dlerror() to see what went wrong
  retval = ropcall("dlerror", "", 0, 0, 0, 0);
  usleep(5000);
  vm_size_t bytesRead;
  char *buf = readmem(retval, &bytesRead);
  printf("dlerror returned: %s\n", buf);

  //const char *fname = "/etc/shadow";
  //snprintf(argMap, 127, "s%luuu", strlen(fname));
  //retval = ropcall("open", argMap, (uint64_t *)fname, (uint64_t *)((uint64_t )O_WRONLY | (uint64_t)O_CREAT), (uint64_t *)0644, 0);
  */
  return 0;
}

/*
  // janky tracer
  uint64_t oldPc=0xaaaaaaaa, oldLr=0xbbbbbbbb, oldSp=0xcccccccc;  
  while(1) {
    thread_suspend(thread);
    thread_abort_safely(thread);

    thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount);
    if(state.__pc != oldPc || state.__lr != oldLr || state.__sp != oldSp) {
      oldPc = state.__pc;
      oldLr = state.__lr;
      oldSp = state.__sp;
      printf("pc: 0x%llx\nlr: 0x%llx\nsp: 0x%llx\n\n", state.__pc, state.__lr, state.__sp);
    }
    fflush(stdout); // do some work
    fflush(stderr);
    
    thread_resume(thread);
  }
*/
