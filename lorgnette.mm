//
//  lorgnette.c
//  liblorgnette
//
//  Created by Dmitry Rodionov on 9/24/14.
//  Copyright (c) 2014 rodionovd. All rights reserved.
//

/** We don't want assert() to be stripped out from release builds. */
#ifdef NDEBUG
	#define RD_REENABLE_NDEBUG NDEBUG
	#undef NDEBUG
#endif
#include <assert.h>
#ifdef RD_REENABLE_NDEBUG
	#define NDEBUG RD_REENABLE_NDEBUG
	#undef RD_REENABLE_NDEBUG
#endif
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <syslog.h>
#include <stdbool.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>

#include "lorgnette.h"
#include "lorgnette-structs.h"

#define RDFailOnError(function, label) \
	do { \
		if (err != KERN_SUCCESS) { \
			syslog(LOG_NOTICE, "[%d] %s failed with error: %s [%d]\n", \
					__LINE__-1, function, mach_error_string(err), err); \
			goto label; \
		} \
	} while(0)

/** This magic Mach-O header flag implies that image was loaded from dyld shared cache */
#define kImageFromSharedCacheFlag 0x80000000
/** @see _copyin_string() */
#define kRemoteStringBufferSize 2048
/** Default base addresses for 32- and 64-bit executables */
#define ki386DefaultBaseAddress 0x1000
#define kx86_64DefaultBaseAddress 0x100000000

int _image_headers_in_task(task_t, const char *, vm_address_t*, uint32_t*, uint64_t*);
static int _image_headers_from_dyld_info32(task_t, task_dyld_info_data_t, const char*, uint32_t*,
										   uint64_t*, uint64_t *);
static int _image_headers_from_dyld_info64(task_t, task_dyld_info_data_t, const char*, uint32_t*,
										   uint64_t*, uint64_t *);
static vm_address_t _scan_remote_image_for_symbol(task_t, vm_address_t, const char *, bool *);
static char *_copyin_string(task_t, vm_address_t);


#pragma mark - Lorgnette

vm_address_t lorgnette_lookup(task_t target, const char *symbol_name)
{
	return lorgnette_lookup_image(target, symbol_name, NULL);
}

vm_address_t lorgnette_lookup_image(task_t target, const char *symbol_name, const char *image_name)
{
	assert(symbol_name);
	assert(strlen(symbol_name) > 0);

	int err = KERN_SUCCESS;
	uint32_t count = 0;
	uint64_t shared_cache_slide = 0x0;
	err = _image_headers_in_task(target, image_name, NULL, &count, &shared_cache_slide);
	if (err != KERN_SUCCESS) {
		return 0;
	}

	vm_address_t *headers = (vm_address_t *)malloc(sizeof(*headers) * count);
	err =_image_headers_in_task(target, image_name, headers, &count, &shared_cache_slide);
	if (err != KERN_SUCCESS) {
		free(headers);
		return 0;
	}
	vm_address_t result = 0;
	bool imageFromSharedCache = 0;
	for (uint32_t i = 0; i < count; i++) {
		vm_address_t image = headers[i];
		result = _scan_remote_image_for_symbol(target, image, symbol_name, &imageFromSharedCache);
		if (result > 0) {
			/** Add ASLR slice only for the main image of the target */
			if (i == 0) {
				// FIXME: dirty hardcoding
				/* Get a relative symbol offset */
				if (result < kx86_64DefaultBaseAddress)  {
					result -= ki386DefaultBaseAddress;
				} else {
					result -= kx86_64DefaultBaseAddress;
				}
				/* The header pointer already have ASLR slice included */
				result += headers[0];
			} else if (!imageFromSharedCache) {
				/**
				 * On some setups dyld shared cache doesn't contain some system libraries.
				 * In this case we have to append a base_address+ASLR value to the result.
				 */
				if (headers[i] > kx86_64DefaultBaseAddress && result < kx86_64DefaultBaseAddress) {
					/* x86_64 target */
					result += headers[i];
				}
				if (headers[i] < kx86_64DefaultBaseAddress && result < ki386DefaultBaseAddress) {
					/* i386 target */
					result += headers[i];
				}
			}
			break;
		};
	}
	free(headers);
	/* Add a slide if our target image was a library from the dyld shared cache */
	if (imageFromSharedCache && result > 0) {
		result += shared_cache_slide;
	}

	return result;
}

#pragma mark - All the interesting stuff
/**
 * @abstract
 * Get a list of load addresses of all mach-o images within the target task.
 * @note
 * These addresses could belong to a foreign address space.
 *
 * @param task
 * the target process
 * @param headers (out)
 * the list of length @p count containing addresses of images loaded into the target task
 * @param count (out)
 * the length of @p headers list
 */
int _image_headers_in_task(task_t task,
						   const char *suggested_image_name,
						   vm_address_t *headers,
						   uint32_t *count,
						   uint64_t *shared_cache_slide)
{
	task_flavor_t flavor = TASK_DYLD_INFO;
	task_dyld_info_data_t data;
	mach_msg_type_number_t number = TASK_DYLD_INFO_COUNT;
	int err = task_info(task, flavor, (task_info_t)&data, &number);
	//RDFailOnError("task_info()", fail);

	if (data.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_32) {
		return _image_headers_from_dyld_info32(task, data, suggested_image_name, count,
											   (unsigned long long *)headers, shared_cache_slide);
	} else {
		return _image_headers_from_dyld_info64(task, data, suggested_image_name, count,
											   (unsigned long long *)headers, shared_cache_slide);
	}

fail:
	return KERN_FAILURE;
}

static
int _image_headers_from_dyld_info64(task_t target,
									task_dyld_info_data_t dyld_info,
									const char *suggested_image_name,
									uint32_t *count,
									uint64_t *headers,
									uint64_t *shared_cache_slide)
{
	assert(count);
	assert(shared_cache_slide);

	int err = KERN_FAILURE;
	struct dyld_all_image_infos_64 infos;
	vm_size_t size = dyld_info.all_image_info_size;
	err = vm_read_overwrite(target, dyld_info.all_image_info_addr, sizeof(infos),
								 (vm_address_t)&infos, &size);
	////RDFailOnError("vm_read_overwrite()", fail);

	*count = infos.infoArrayCount;
	*shared_cache_slide = infos.sharedCacheSlide;

	size = sizeof(struct dyld_image_info_64) * (*count);
	struct dyld_image_info_64 *array = (struct dyld_image_info_64 *)malloc((size_t)size);
	err = vm_read_overwrite(target, (vm_address_t)infos.infoArray, size,
								 (vm_address_t)array, &size);
	////RDFailOnError("vm_read_overwrite()", fail);

	bool should_find_particular_image = (suggested_image_name != NULL);
	if (headers) {
		for (uint32_t i = 0; i < *count; i++) {
			/// FIXME: Find a real location of the first image path
			/* We have to always include the first image in the headers list
			 * because an image filepath's address is slided with an unknown offset,
			 * so we can't read the image name directly. */
			if (!should_find_particular_image || i == 0) {
				headers[i] = (vm_address_t)array[i].imageLoadAddress;
			} else {
				char *image_name = _copyin_string(target, array[i].imageFilePath);
				bool not_found = ({
					strcmp(suggested_image_name, image_name) &&
					strcmp(suggested_image_name, basename(image_name));
				});
				free(image_name);
				if (not_found) {
					headers[i] = 0;
				} else {
					headers[i] = (vm_address_t)array[i].imageLoadAddress;
					break;
				}
			}
		}
	}

	free(array);
	return KERN_SUCCESS;

fail:
	free(array);
	return KERN_FAILURE;
}


static
int _image_headers_from_dyld_info32(task_t target,
									task_dyld_info_data_t dyld_info,
									const char *suggested_image_name,
									uint32_t *count,
									uint64_t *headers,
									uint64_t *shared_cache_slide)
{
	assert(count);
	assert(shared_cache_slide);

	int err = KERN_FAILURE;
	struct dyld_all_image_infos_32 infos;
	vm_size_t size = dyld_info.all_image_info_size;
	err = vm_read_overwrite(target, dyld_info.all_image_info_addr, size,
								 (vm_address_t)&infos, &size);
	//RDFailOnError("vm_read_overwrite()", fail);

	*count = infos.infoArrayCount;
	*shared_cache_slide = infos.sharedCacheSlide;

	size = sizeof(struct dyld_image_info_32) * (*count);
	struct dyld_image_info_32 *array = (struct dyld_image_info_32 *)malloc((size_t)size);
	err = vm_read_overwrite(target, (vm_address_t)infos.infoArray, size,
								 (vm_address_t)array, &size);
	//RDFailOnError("vm_read_overwrite()", fail);

	bool should_find_particular_image = (suggested_image_name != NULL);
	if (headers) {
		for (uint32_t i = 0; i < *count; i++) {
			/// FIXME: Find a real location of the first image path
			/* We have to always include the first image in the headers list
			 * because an image filepath's address is slided with an unknown offset,
			 * so we can't read the image name directly. */
			if (!should_find_particular_image || i == 0) {
				headers[i] = (vm_address_t)array[i].imageLoadAddress;
			} else {
				char *image_name = _copyin_string(target, array[i].imageFilePath);
				bool not_found = ({
					strcmp(suggested_image_name, image_name) &&
					strcmp(suggested_image_name, basename(image_name));
				});
				free(image_name);
				if (not_found) {
					headers[i] = 0;
				} else {
					headers[i] = (vm_address_t)array[i].imageLoadAddress;
					break;
				}
			}
		}
	}

	free(array);
	return KERN_SUCCESS;

fail:
	free(array);
	return KERN_FAILURE;
}

/**
 *
 */
static
vm_address_t _scan_remote_image_for_symbol(task_t task,
												vm_address_t remote_header,
												const char *symbol_name,
												bool *imageFromSharedCache)
{
	assert(symbol_name);
	assert(imageFromSharedCache);
	int err = KERN_FAILURE;

	if (remote_header == 0) {
		return 0;
	}

	vm_size_t size = sizeof(struct mach_header);
	struct mach_header header = {0};
	err = vm_read_overwrite(task, remote_header, size, (vm_address_t)&header, &size);
	//RDFailOnError("vm_read_overwrite()", fail);

	bool sixtyfourbit = (header.magic == MH_MAGIC_64);
	*imageFromSharedCache = ((header.flags & kImageFromSharedCacheFlag) == kImageFromSharedCacheFlag);

	/* We don't support anything but i386 and x86_64 */
	if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64) {
		syslog(LOG_NOTICE, "liblorgnette ERROR: found image with unsupported architecture"
				"at %p, skipping it.\n", (void *)remote_header);
		return 0;
	}

	/**
	 * Let's implement some nlist()
	 */
	vm_address_t symtab_addr = 0;
	vm_address_t linkedit_addr = 0;
	vm_address_t text_addr = 0;

	size_t mach_header_size = sizeof(struct mach_header);
	if (sixtyfourbit) {
		mach_header_size = sizeof(struct mach_header_64);
	}
	vm_address_t command_addr = remote_header + mach_header_size;
	struct load_command command = {0};
	size = sizeof(command);

	for (uint32_t i = 0; i < header.ncmds; i++) {
		err = vm_read_overwrite(task, command_addr, size, (vm_address_t)&command, &size);
		//RDFailOnError("vm_read_overwrite()", fail);

		if (command.cmd == LC_SYMTAB) {
			symtab_addr = command_addr;
		} else if (command.cmd == LC_SEGMENT || command.cmd == LC_SEGMENT_64) {
			/* struct load_command only has two fields (cmd & cmdsize), while its "child" type
			 * struct segment_command has way more fields including `segname` at index 3, so we just
			 * pretend that we have a real segment_command and skip first two fields away */
			size_t segname_field_offset = sizeof(command);
			vm_address_t segname_addr = command_addr + segname_field_offset;
			char *segname = _copyin_string(task, segname_addr);
			if (0 == strcmp(SEG_TEXT, segname)) {
				text_addr = command_addr;
			} else if (0 == strcmp(SEG_LINKEDIT, segname)) {
				linkedit_addr = command_addr;
			}
			free(segname);
		}
		// go to next load command
		command_addr += command.cmdsize;
	}

	if (!symtab_addr || !linkedit_addr || !text_addr) {
		syslog(LOG_NOTICE, "Invalid Mach-O image header, skipping...\n");
		return 0;
	}

	struct symtab_command symtab = {0};
	size = sizeof(struct symtab_command);
	err = vm_read_overwrite(task, symtab_addr, size, (vm_address_t)&symtab, &size);
	//RDFailOnError("vm_read_overwrite", fail);

	// FIXME: find a way to remove the copypasted code below
	// These two snippets share all the logic, but differs in structs and integers
	// they use for reading the data from a target process (32- or 64-bit layout).
	if (sixtyfourbit) {
		struct segment_command_64 linkedit = {0};
		size = sizeof(struct segment_command_64);
		err = vm_read_overwrite(task, linkedit_addr, size,
									 (vm_address_t)&linkedit, &size);
		//RDFailOnError("vm_read_overwrite", fail);
		struct segment_command_64 text = {0};
		err = vm_read_overwrite(task, text_addr, size, (vm_address_t)&text, &size);
		//RDFailOnError("vm_read_overwrite", fail);

		uint64_t file_slide = linkedit.vmaddr - text.vmaddr - linkedit.fileoff;
		uint64_t strings = remote_header + symtab.stroff + file_slide;
		uint64_t sym_addr = remote_header + symtab.symoff + file_slide;

		for (uint32_t i = 0; i < symtab.nsyms; i++) {
			struct nlist_64 sym = {{0}};
			size = sizeof(struct nlist_64);
			err = vm_read_overwrite(task, sym_addr, size, (vm_address_t)&sym, &size);
			//RDFailOnError("vm_read_overwrite", fail);
			sym_addr += size;

			if (!sym.n_value) continue;

			uint64_t symname_addr = strings + sym.n_un.n_strx;
			char *symname = _copyin_string(task, symname_addr);
			/* Ignore the leading "_" character in a symbol name */
			if (0 == strcmp(symbol_name, symname+1)) {
				free(symname);
				return (vm_address_t)sym.n_value;
			}
			free(symname);
		}
	} else {
		struct segment_command linkedit = {0};
		size = sizeof(struct segment_command);
		err = vm_read_overwrite(task, linkedit_addr, size,
									 (vm_address_t)&linkedit, &size);
		//RDFailOnError("vm_read_overwrite", fail);
		struct segment_command text = {0};
		err = vm_read_overwrite(task, text_addr, size, (vm_address_t)&text, &size);
		//RDFailOnError("vm_read_overwrite", fail);

		uint32_t file_slide = linkedit.vmaddr - text.vmaddr - linkedit.fileoff;
		uint32_t strings = (uint32_t)remote_header + symtab.stroff + file_slide;
		uint32_t sym_addr = (uint32_t)remote_header + symtab.symoff + file_slide;

		for (uint32_t i = 0; i < symtab.nsyms; i++) {
			struct nlist sym = {{0}};
			size = sizeof(struct nlist);
			err = vm_read_overwrite(task, sym_addr, size, (vm_address_t)&sym, &size);
			//RDFailOnError("vm_read_overwrite", fail);
			sym_addr += size;

			if (!sym.n_value) continue;

			uint32_t symname_addr = strings + sym.n_un.n_strx;
			char *symname = _copyin_string(task, symname_addr);
			/* Ignore the leading "_" character in a symbol name */
			if (0 == strcmp(symbol_name, symname+1)) {
				free(symname);
				return (vm_address_t)sym.n_value;
			}
			free(symname);
		}
	}

fail:
	return 0;
}

/**
 * @abstract
 * Copy a string from the target task's address space to current address space.
 *
 * @param task
 * The target task.
 * @param pointer
 * The address of a string to copyin.
 *
 * @return
 * A pointer to a string. It may be NULL.
 */
static char *_copyin_string(task_t task, vm_address_t pointer)
{
	assert(pointer > 0);
	int err = KERN_FAILURE;

	/* Since calls to vm_read_overwrite() are expensive we'll just use
	 * a rather big buffer insead of reading char-by-char.
	 */
	// FIXME: what about the size of this buffer?
	// Users can requst symbols with very long names (e.g. C++ mangled method names, etc)
	char buf[kRemoteStringBufferSize] = {0};
	vm_size_t sample_size = sizeof(buf);
	err = vm_read_overwrite(task, pointer, sample_size,
								 (vm_address_t)&buf, &sample_size);
	assert(err == KERN_SUCCESS);
	buf[kRemoteStringBufferSize-1] = '\0';

	char *result = strdup(buf);
	return result;
}