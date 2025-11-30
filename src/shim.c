/**
 * Copyright (C) 2025 Florian Marrero Liestmann
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
 *
 * Author: Florian Marrero Liestmann <f.m.liestmann@fx-ttr.de>
 * File: shim.c
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <fcntl.h>

int ll_create_ruleset(const struct landlock_ruleset_attr *const attr,
                  const size_t size, const __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
} 
