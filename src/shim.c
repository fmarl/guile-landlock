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

#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/landlock.h>
#include <fcntl.h>
#include <sys/prctl.h>

static inline int ll_create_ruleset(const struct landlock_ruleset_attr *const attr,
				    const size_t size, const __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int ll_add_rule(const int ruleset_fd,
			      const enum landlock_rule_type rule_type,
			      const void *const rule_attr,
			      const __u32 flags) {
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static inline int ll_restrict_self(const int ruleset_fd, const __u32 flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

int scm_ll_abi_version() {
    return ll_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}

int scm_ll_create_ruleset(long handled_access_fs, long handled_access_net,
                          long scoped) {
    struct landlock_ruleset_attr attr = {.handled_access_fs = handled_access_fs,
					 .handled_access_net = handled_access_net,
					 .scoped = scoped};
    
    return ll_create_ruleset(&attr, sizeof(attr), 0);
}

int scm_ll_add_net_port_rule(int ruleset_fd, long allowed_access, int port) {
    struct landlock_net_port_attr attr = {.allowed_access = allowed_access,
					  .port = port};

    return ll_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &attr, 0);
}

int scm_ll_add_path_beneath_rule(int ruleset_fd, long allowed_access,
                                 char *path, int ignore_if_missing) {
    struct landlock_path_beneath_attr path_beneath = {
	.allowed_access = allowed_access
    };
  
    path_beneath.parent_fd = open(path, O_PATH | O_CLOEXEC);

    if (path_beneath.parent_fd < 0) {
	if ((path_beneath.parent_fd == -ENOENT || path_beneath.parent_fd == -EPERM) && ignore_if_missing) {
	    path_beneath.parent_fd = 0;
        }
	
	return path_beneath.parent_fd;
    }

    int ret = ll_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
    close(path_beneath.parent_fd);
    
    return ret;
}

int scm_ll_restrict_self(int ruleset_fd) {
    int ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret) {
	return ret;
    }

    return ll_restrict_self(ruleset_fd, 0);
}
