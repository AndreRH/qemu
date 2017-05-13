/*
 *  mmap support for qemu
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"

#include "qemu.h"
#include "qemu-common.h"
#include "translate-all.h"

//#define DEBUG_MMAP

void mmap_lock(void)
{
    qemu_log("mmap_lock unimplemented.\n");
}

void mmap_unlock(void)
{
    qemu_log("mmap_unlock unimplemented.\n");
}

bool have_mmap_lock(void)
{
    qemu_log("have_mmap_lock unimplemented.\n");
    return false;
}

/* Grab lock to make sure things are in a consistent state after fork().  */
void mmap_fork_start(void)
{
    qemu_log("mmap_fork_start unimplemented.\n");
}

void mmap_fork_end(int child)
{
    qemu_log("mmap_fork_end unimplemented.\n");
}

int target_mprotect(abi_ulong start, abi_ulong len, int prot)
{
    qemu_log("target_mprotect unimplemented.\n");
    return -EINVAL;
}
