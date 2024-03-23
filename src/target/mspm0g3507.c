/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright (C) 2022 dpf ("neutered") <weasel@cs.stanford.edu>
 * Written by dpf ("neutered") <weasel@cs.stanford.edu>
 *
 * Copyright (C) 2023 1BitSquared <info@1bitsquared.com>
 * Modified by Rachel Mant <git@dragonmux.network>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file implements MSPM0 target specific functions for detecting
 * the device, providing the XML memory map and Flash memory programming.
 *
 * References:
 * TI doc - SLAU846A
 *   MSPM0 G-Series Technical Reference Manual (https://www.ti.com/lit/ug/slau846a/slau846a.pdf)
 */

#include "general.h"
#include "target.h"
#include "target_internal.h"
#include "buffer_utils.h"

#define MSPM0G3507_FLASH_CTRL_BASE 0x400fd000U
#define MSPM0G3507_SYS_CTRL_BASE   0x400fe000U

#define MSPM0G3507_FLASH_BASE  0x00000000U
#define MSPM0G3507_SRAM_BASE   0x20000000U
#define MSPM0G3507_PERIPH_BASE 0x400CD000U

#define MSPM0G3507_CPUID 0xE000ED00U

#define MSPM0G3507_CMD_TYPE_BASE                 MSPM0G3507_PERIPH_BASE + 0x1104U
#define MSPM0G3507_CMD_TYPE_COMMAND_NOOP         0x0U
#define MSPM0G3507_CMD_TYPE_COMMAND_PROGRAM      0x1U
#define MSPM0G3507_CMD_TYPE_COMMAND_ERASE        0x2U
#define MSPM0G3507_CMD_TYPE_COMMAND_READ_VERIFY  0x3U
#define MSPM0G3507_CMD_TYPE_COMMAND_BLANK_VERIFY 0x6U

#define MSPM0G3507_CMD_TYPE_SIZE_1_word (1U << 4U)

#define MSPM0G3507_CMD_CTL             MSPM0G3507_PERIPH_BASE + 0x1108U
#define MSPM0G3507_CMD_CTL_MAIN_REGION 0x1U

#define MSPM0G3507_CMD_EXEC MSPM0G3507_PERIPH_BASE + 0x1100U

#define MSPM0G3507_STAT_CMD_BASE            MSPM0G3507_PERIPH_BASE + 0x13D0U
#define MSPM0G3507_STAT_CMD_CMD_DONE        (1U << 0U)
#define MSPM0G3507_STAT_CMD_CMD_PASS        (1U << 1U)
#define MSPM0G3507_STAT_CMD_CMD_IN_PROGRESS (1U << 2U)

#define MSPM0G3507_CMD_ADDR MSPM0G3507_PERIPH_BASE + 0x1120U

#define MSPM0G3507_CMD_BYTE_EN_BASE MSPM0G3507_PERIPH_BASE + 0x1124U
#define MSPM0G3507_CMD_BYTE_EN_ADDR 0xFU

#define MSPM0G3507_CMD_DATA_BASE MSPM0G3507_PERIPH_BASE + 0x1130U
#define MSPM0G3507_CMD_DATA_0    MSPM0G3507_CMD_DATA_BASE
#define MSPM0G3507_CMD_DATA_1    MSPM0G3507_CMD_DATA_0 + 0x4U

#define CMDWEPROTA MSPM0G3507_PERIPH_BASE + 0x11D0U
#define CMDWEPROTB MSPM0G3507_PERIPH_BASE + 0x11D4U

/* The Flash routines can write only 8 bytes at a time, so let the target Flash layer take care of the rest */
#define MSPM0G3507_FLASH_WRITE_SIZE 8U

typedef struct mspM0g3507_flash {
	target_flash_s target_flash;
	uint16_t flash_key;
} mspM0g3507_flash_s;

static bool mspM0g3507_flash_erase(target_flash_s *flash, target_addr_t addr, size_t length);
static bool mspM0g3507_flash_write(target_flash_s *flash, target_addr_t dest, const void *src, size_t length);
static bool mspM0g3507_mass_erase(target_s *target);

static void mspM0g3507_add_flash(
	target_s *const target, const uint32_t sector_size, const uint32_t base, const size_t length)
{
	DEBUG_WARN("Adding flash\n");
	mspM0g3507_flash_s *const flash = calloc(1, sizeof(*flash));
	if (flash == NULL) {
		DEBUG_WARN("calloc: failed in %s\n", __func__);
		return;
	}

	target_flash_s *target_flash = &flash->target_flash;
	target_flash->start = base;
	target_flash->length = length;
	target_flash->blocksize = sector_size;
	target_flash->writesize = MSPM0G3507_FLASH_WRITE_SIZE;
	target_flash->erase = mspM0g3507_flash_erase;
	target_flash->write = mspM0g3507_flash_write;
	target_flash->erased = 0xff;
	target_add_flash(target, target_flash);
}

bool mspm0g3507_probe(target_s *const target)
{
	const uint32_t devid0 = target_mem_read32(target, 0xE000ED00);
	DEBUG_WARN("%s: Device ID %" PRIx32 "\n", __func__, devid0);

	if (devid0 != 0x410cc601) {
		return false;
	}

	target->driver = "MSPM0G3507";
	target->mass_erase = mspM0g3507_mass_erase;

	const uint32_t sram_size = 0x3FFFFFFF - 0x20000000;
	target_add_ram(target, MSPM0G3507_SRAM_BASE, sram_size);

	const uint32_t flash_size = 128 * 1024;

	const uint32_t flash_sector_size = 1024;

	mspM0g3507_add_flash(target, flash_sector_size, MSPM0G3507_FLASH_BASE, flash_size);

	return true;
}

static bool mspM0g3507_exec_flash(target_s *const target, const target_addr_t addr)
{
}

/* Erase from addr for length bytes */
static bool mspM0g3507_flash_erase(target_flash_s *const target_flash, const target_addr_t addr, const size_t length)
{
	(void)length;
	target_s *const target = target_flash->t;

	DEBUG_WARN("Erasing: %ul, %ul\n", addr, length);
	/*
	 * The target Flash layer guarantees we're called at the start of each target_flash->blocksize
	 * so we only need to trigger the erase of the Flash sector pair and that logic will take care of the rest.
	 */
	uint32_t cmd_type = target_mem_read32(target, MSPM0G3507_CMD_TYPE_BASE);

	// set bits 0-2, 4-6
	cmd_type = cmd_type & 0xFFFFFF18;
	cmd_type = cmd_type | MSPM0G3507_CMD_TYPE_COMMAND_ERASE;
	cmd_type = cmd_type | 0b1000000;

	target_mem_write32(target, MSPM0G3507_CMD_TYPE_BASE, cmd_type);

	target_mem_write32(target, MSPM0G3507_CMD_ADDR, addr);

	uint32_t sector = addr / 1024;

	// Disable dynamic memory protection
	/*if (sector < 32) {
		target_mem_write32(target, CMDWEPROTA, sector);
	}
	else {
		target_mem_write32(target, CMDWEPROTB, sector - 32);
	}*/

	target_mem_write32(target, CMDWEPROTA, 0);
	target_mem_write32(target, CMDWEPROTB, 0);

	target_mem_write32(target, MSPM0G3507_CMD_EXEC, 1);

	uint32_t status = target_mem_read32(target, MSPM0G3507_STAT_CMD_BASE);
	uint32_t last_status = 0xFFFFFFFF;

	while ((status & MSPM0G3507_STAT_CMD_CMD_DONE) == 0) {
		if (status != 0 && status != last_status) {
			DEBUG_WARN("Erase status: %" PRIx32 "\n", status);
			last_status = status;
		}
		status = target_mem_read32(target, MSPM0G3507_STAT_CMD_BASE);
	}
	return true;
}

/* Program flash */
static bool mspM0g3507_flash_write(
	target_flash_s *const target_flash, target_addr_t dest, const void *const src, const size_t length)
{
	(void)length;
	target_s *const target = target_flash->t;

	DEBUG_WARN("Writing: 0x%" PRIx32 ", 0x%" PRIx32 ", %d, 0x%" PRIx64 "\n", dest, length, dest / 1024,
		*(const uint64_t *)src);
	/*
	 * The target Flash layer guarantees that we're called with a length that's a complete write size
	 * and that the source data buffer is filled with the erase byte value so we don't disturb unwritten
	 * Flash. With the write size set to 4 to match how many bytes we can write in one go, that
	 * allows this routine to go 32-bit block at a time efficiently, passing the complexity up a layer.
	 */

	uint32_t cmd_type = target_mem_read32(target, MSPM0G3507_CMD_TYPE_BASE);

	// set bits 0-2, 4-6
	cmd_type = cmd_type & 0xFFFFFFF8;
	cmd_type = cmd_type | MSPM0G3507_CMD_TYPE_COMMAND_PROGRAM;
	cmd_type = cmd_type & 0b0001111;

	target_mem_write32(target, MSPM0G3507_CMD_TYPE_BASE, cmd_type);

	target_mem_write32(target, MSPM0G3507_CMD_CTL, 0);

	target_mem_write32(target, MSPM0G3507_CMD_ADDR, dest);

	uint32_t sector = dest / 1024;

	// Disable dynamic memory protection
	/*if (sector < 32) {
		target_mem_write32(target, CMDWEPROTA, sector);
	}
	else {
		target_mem_write32(target, CMDWEPROTB, sector - 32);
	}*/

	target_mem_write32(target, CMDWEPROTA, 0);
	target_mem_write32(target, CMDWEPROTB, 0);

	target_mem_write32(target, MSPM0G3507_CMD_DATA_0, read_le4((const uint8_t *)src, 0));
	target_mem_write32(target, MSPM0G3507_CMD_DATA_1, read_le4((const uint8_t *)src, 4));

	target_mem_write32(target, MSPM0G3507_CMD_EXEC, 1);

	uint32_t status = target_mem_read32(target, MSPM0G3507_STAT_CMD_BASE);
	uint32_t last_status = 0xFFFFFFFF;

	while ((status & MSPM0G3507_STAT_CMD_CMD_DONE) == 0) {
		if (status != 0 && status != last_status) {
			//DEBUG_WARN("Write status: %" PRIx32 "\n", status);
			last_status = status;
		}
		status = target_mem_read32(target, MSPM0G3507_STAT_CMD_BASE);
	}

	/*while ((target_mem_read32(target, MSPM0G3507_STAT_CMD_BASE) & MSPM0G3507_STAT_CMD_CMD_DONE) == 0) {
		uint32_t status = target_mem_read32(target, MSPM0G3507_STAT_CMD_BASE);
		if (status != 0)
		{
			DEBUG_WARN("Status: %" PRIx32 "\n", status);
		}
	}*/
	return true;
}

/* Mass erases the Flash */
static bool mspM0g3507_mass_erase(target_s *const target)
{
	return false;
	/*const mspM0g3507_flash_s *const flash = (mspM0g3507_flash_s *)target->flash;
	platform_timeout_s timeout;
	platform_timeout_set(&timeout, 500);
	target_mem_write32(target, MSPM0G3507_FLASH_CTRL, (flash->flash_key << 16U) | MSPM0G3507_FLASH_CTRL_MASS_ERASE);
	while (target_mem_read32(target, MSPM0G3507_FLASH_CTRL) & MSPM0G3507_FLASH_CTRL_MASS_ERASE)
		target_print_progress(&timeout);
	return true;*/
}
