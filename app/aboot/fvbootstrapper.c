#include <app.h>
#include <debug.h>
#include <arch/arm.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <kernel/thread.h>
#include <arch/ops.h>

#include <dev/flash.h>
#include <dev/flash-ubi.h>
#include <lib/ptable.h>
#include <dev/keys.h>
#include <dev/fbcon.h>
#include <baseband.h>
#include <target.h>
#include <mmc.h>
#include <partition_parser.h>
#include <platform.h>
#include <crypto_hash.h>
#include <malloc.h>
#include <boot_stats.h>
#include <sha.h>
#include <platform/iomap.h>
#include <boot_device.h>
#include <boot_verifier.h>
#include <image_verify.h>
#include <decompress.h>
#include <platform/timer.h>
#include <sys/types.h>

#include <reboot.h>
#include "image_verify.h"
#include "recovery.h"
#include "bootimg.h"
#include "fastboot.h"
#include "sparse_format.h"
#include "meta_format.h"
#include "mmc.h"
#include "devinfo.h"
#include "board.h"
#include "scm.h"
#include "mdtp.h"
#include "secapp_loader.h"
#include "fvbootstrapper.h"
#include "elf.h"
#include <menu_keys_detect.h>
#include <display_menu.h>

BUF_DMA_ALIGN(fd_elf_hdr_buf, BOOT_IMG_MAX_PAGE_SIZE);

bool verify_fd_elf_header(Elf64_Ehdr *bl_elf_hdr);
int check_fd_addr_range_overlap(uintptr_t start, uint32_t size);
int check_ddr_addr_range_bound(uintptr_t start, uint32_t size);

extern void platform_uninit(void);
extern void target_uninit(void);

bool verify_fd_elf_header(Elf64_Ehdr *bl_elf_hdr)
{
    // Sanity check: Signature
	if (bl_elf_hdr->e_ident[EI_MAG0] != ELFMAG0 ||
		bl_elf_hdr->e_ident[EI_MAG1] != ELFMAG1 ||
		bl_elf_hdr->e_ident[EI_MAG2] != ELFMAG2 ||
		bl_elf_hdr->e_ident[EI_MAG3] != ELFMAG3
		)
	{
		dprintf(ALWAYS, "Verifier: Payload has invalid ELF magic.\n");
		return false;
	}
    else
    {
        dprintf(ALWAYS, "Verifier: Payload has valid ELF magic.\n");
    }

    // Sanity check: type
	if (bl_elf_hdr->e_machine != EM_AARCH64)
	{
		dprintf(ALWAYS, "Verifier: ELF reports invalid architecture.\n");
		return false;
	}
    else
    {
        dprintf(ALWAYS, "Verifier: ELF reports valid architecture.\n");
    }

    // Sanity check: exec
	if (bl_elf_hdr->e_type != ET_EXEC)
	{
		dprintf(ALWAYS, "Verifier: ELF reports invalid type.\n");
        return false;
	}
    else
    {
        dprintf(ALWAYS, "Verifier: ELF reports valid type.\n");
    }

    // Sanity check: program header entries. At least one should present.
	if (bl_elf_hdr->e_phnum < 1)
	{
		dprintf(ALWAYS, "Verifier: Program header entries not found.\n");
		return false;
	}
    else
    {
        dprintf(ALWAYS, "Verifier: %d program header entries found.\n", bl_elf_hdr->e_phnum);
    }

    // Initial check passed
    // Memory allocation check will be performed upon ELF load
    return true;
}

/* Function to check if the memory address range falls within the aboot
 * boundaries.
 * start: Start of the memory region
 * size: Size of the memory region
 */
int check_fd_addr_range_overlap(uintptr_t start, uint32_t size)
{
	/* Check for boundary conditions. */
	if ((UINT_MAX - start) < size)
		return -1;

	/* Check for memory overlap. */
	if ((start < MEMBASE) && ((start + size) <= MEMBASE))
		return 0;
	else if (start >= (MEMBASE + MEMSIZE))
		return 0;
	else
		return -1;
}

bool bootstrap_elf64(void)
{
    Elf64_Ehdr *fd_elf64_hdr = (void*) fd_elf_hdr_buf;
    Elf64_Phdr *fd_elf64_pg_hdr = (void*) NULL;

    int ph_idx = 0;
    int boot_partition_index = INVALID_PTN;
    unsigned long long boot_partition_offset = 0;
    unsigned long long load_section_offset = 0;
    unsigned long long load_section_length = 0;
    unsigned long long load_section_length_actual = 0;
    unsigned long long fd_entry_point = 0;
    unsigned long long offset = 0;
    unsigned char *image_addr = 0;

    uint32_t page_size = 0;
    uint32_t page_mask = 0;

    page_size = mmc_page_size();

    if (page_size == 0)
    {
        dprintf(CRITICAL, "ELF Verifier: Invalid page size\n");
        goto exit;
    }
    page_mask = page_size - 1;

    boot_partition_index = partition_get_index("boot");
    boot_partition_offset = partition_get_offset(boot_partition_index);
    if (boot_partition_offset == 0)
    {
        dprintf(CRITICAL, "ELF Verifier: Failed to find boot partition\n");
        goto exit;
    }

    /* Set Lun for boot & recovery partitions */
	mmc_set_lun(partition_get_lun(boot_partition_index));

    /* Read ELF Header */
    if (mmc_read(boot_partition_offset + offset, (uint32_t *) fd_elf_hdr_buf, page_size))
    {
        dprintf(CRITICAL, "ELF Verifier: Cannot read FD ELF header\n");
        goto exit;
    }

    /* Run some checks */
    if (!verify_fd_elf_header(fd_elf64_hdr))
    {
        dprintf(CRITICAL, "ELF Verifier: Image failed test\n");
        goto exit;
    }

    /* Read program section */
    if (fd_elf64_hdr->e_phoff == 0 || fd_elf64_hdr->e_phoff < sizeof(Elf64_Ehdr))
    {
        dprintf(CRITICAL, "ELF Verifier: Invalid program header offset\n");
        goto exit;
    }

    fd_entry_point = fd_elf64_hdr->e_entry;
    offset = fd_elf64_hdr->e_phoff;

    /* Check if we need to read more pages */
    if ((offset + sizeof(Elf64_Phdr) * (fd_elf64_hdr->e_phnum)) > page_size)
    {
        dprintf(CRITICAL, "ELF Verifier: Too many program sections\n");
        goto exit;
    }

    fd_elf64_pg_hdr = (void*) (fd_elf_hdr_buf + offset);
    for (ph_idx = 0; ph_idx < fd_elf64_hdr->e_phnum; ph_idx++)
    {
        /* Check if it is LOAD section */
        if (fd_elf64_pg_hdr->p_type != PT_LOAD)
        {
            dprintf(ALWAYS, "Section %d skipped because it is not LOAD\n", ph_idx);
            goto updateoffset;
        }

        /* Sanity check: PA = VA, PA = entry_point, memory size = file size */
        if (fd_elf64_pg_hdr->p_paddr != fd_elf64_pg_hdr->p_vaddr)
        {
            dprintf(ALWAYS, "LOAD section %d skipped due to identity mapping vioaltion\n", ph_idx);
            goto updateoffset;
        }

        if (fd_elf64_pg_hdr->p_filesz != fd_elf64_pg_hdr->p_memsz)
        {
            dprintf(ALWAYS, "LOAD section %d skipped due to inconsistent size\n", ph_idx);
            goto updateoffset;
        }

        if (fd_elf64_pg_hdr->p_paddr != fd_entry_point)
        {
            dprintf(ALWAYS, "LOAD section %d skipped due to entry point violation\n", ph_idx);
            goto updateoffset;
        }

        load_section_offset = fd_elf64_pg_hdr->p_offset;
        load_section_length = fd_elf64_pg_hdr->p_filesz;
        break;

    updateoffset:
        fd_elf64_pg_hdr = (void*) (fd_elf64_pg_hdr + sizeof(Elf64_Phdr));
    }

    if (load_section_offset == 0 || load_section_length == 0)
    {
        dprintf(ALWAYS, "ELF does not contain valid LOAD section\n");
        goto exit;
    }

    if (load_section_offset % page_size != 0)
    {
        dprintf(CRITICAL, "FD entry offset does not match block device page size\n");
        goto exit;
    }

    dprintf(ALWAYS, "FD entry point = 0x%llx, partition offset = 0x%llx, size = 0x%llx\n",
        fd_entry_point, load_section_offset, load_section_length);

    /* Load FD content into scratch memory region */
    offset = load_section_offset;
    load_section_length_actual = ROUND_TO_PAGE(load_section_length, page_mask);
    image_addr = (unsigned char *) target_get_scratch_address();

    if (check_fd_addr_range_overlap((uintptr_t) image_addr, load_section_length_actual))
	{
		dprintf(CRITICAL, "FD buffer address overlaps with aboot addresses.\n");
		goto exit;
	}

    if (mmc_read(boot_partition_offset + offset, (void*) image_addr, load_section_length_actual))
    {
        dprintf(CRITICAL, "ERROR: Cannot read UEFI FD\n");
        goto exit;
    }

    /* Loaded into memory */
    dprintf(ALWAYS, "UEFI FD loaded into memory\n");
    fd_entry_point = VA(fd_entry_point);

    if (check_fd_addr_range_overlap(fd_entry_point, load_section_length_actual))
    {
        dprintf(CRITICAL, "ERROR: Invalid UEFI FD memory configuration\n");
        goto exit;
    }

    /* Move to correct position */
    memmove((void*) (addr_t) fd_entry_point, image_addr, load_section_length_actual);
    dprintf(ALWAYS, "UEFI FD ready.\n");

    /* Launch FD */

    /* Perform target specific cleanup */
	target_uninit();

    enter_critical_section();

    /* do any platform specific cleanup before kernel entry */
	platform_uninit();

	arch_disable_cache(UCACHE);

    #if ARM_WITH_MMU
	arch_disable_mmu();
    #endif

    scm_elexec_call((paddr_t) fd_entry_point, (paddr_t) NULL);

exit:
    // If we are here, that means something wrong
    return false;
}