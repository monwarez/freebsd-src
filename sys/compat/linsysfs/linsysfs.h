/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Dmitry Chagin <dchagin@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _COMPAT_LINSYSFS_LINSYSFS_H_
#define _COMPAT_LINSYSFS_LINSYSFS_H_

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_LINSYSFS);
#endif

extern struct pfs_node *net;

void	linsysfs_net_init(void);
void	linsysfs_net_uninit(void);

typedef struct pfs_node *linsysfs_bus_cb_t(device_t, device_t,
		    struct pfs_node *, struct pfs_node *);

void linsysfs_bus_drm(struct pfs_node *, struct pfs_node *, device_t);

int linsysfs_fill_data(PFS_FILL_ARGS);
char *linsysfs_full_pfs_path(const struct pfs_node *);

struct pfs_node *linsysfs_create_dir(struct pfs_node *, const char *,
		    pfs_attr_t, pfs_vis_t, pfs_destroy_t);
struct pfs_node	*linsysfs_create_file(struct pfs_node *, const char *,
		    pfs_fill_t, pfs_attr_t, pfs_vis_t,
		    pfs_destroy_t, int, void *);
struct pfs_node	*linsysfs_create_link(struct pfs_node *, const char *,
		    pfs_fill_t, pfs_attr_t, pfs_vis_t,
		    pfs_destroy_t, int, void *);
struct pfs_node	*linsysfs_find_pcinode(device_t);


#endif /* _COMPAT_LINSYSFS_LINSYSFS_H_ */
