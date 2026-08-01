/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/sbuf.h>

#include <dev/pci/pcivar.h>

#include <fs/pseudofs/pseudofs.h>

#include <compat/linsysfs/linsysfs.h>
#include <linux/device.h>

/*
 * Filler function for drm uevent file.
 */
static int
linsysfs_drm_fill_uevent(PFS_FILL_ARGS)
{
	device_t bsddev = pn->pn_data;
	struct device *dev;

	/*
	 * XXX. bsddev can die, drm-kmod will delete it on unregister path.
	 */
	dev = device_get_softc(bsddev);
	if (dev == NULL)
		return (-1);
	return (sbuf_printf(sb,
	    "MAJOR=%d\nMINOR=%d\nDEVNAME=dri/%s\nDEVTYPE=drm_minor\n",
	    MAJOR(dev->devt), MINOR(dev->devt), dev_name(dev)));
}

/*
 * Filler function for drm dev file.
 */
static int
linsysfs_drm_fill_dev(PFS_FILL_ARGS)
{
	device_t bsddev = pn->pn_data;
	struct device *dev;

	/*
	 * XXX. bsddev can die, drm-kmod will delete it on unregister path.
	 */
	dev = device_get_softc(bsddev);
	if (dev == NULL)
		return (-1);
	return (sbuf_printf(sb, "%d:%d", MAJOR(dev->devt), MINOR(dev->devt)));
}

/*
 * Filler function for symlink from drm/device to PCI device.
 */
static int
linsysfs_drm_fill_vgapci(PFS_FILL_ARGS)
{
	struct pfs_node *node = pn->pn_data;
	char *path;

	path = linsysfs_full_pfs_path(node);
	sbuf_printf(sb, "../../../../../%s", path);
	free(path, M_TEMP);
	return (0);
}

/*
 * Filler function for symlink from dev/char to drm device.
 */
static int
linsysfs_drm_fill_charlink(PFS_FILL_ARGS)
{
	struct pfs_node *node = pn->pn_data;
	char *path;

	path = linsysfs_full_pfs_path(node);
	sbuf_printf(sb, "../../%s", path);
	free(path, M_TEMP);
	return (0);
}

/*
 * Filler function for drm childrens.
 */
#define DRM_DEV "drm"
void
linsysfs_bus_drm(struct pfs_node *devdir, struct pfs_node *chardir,
    device_t bsddev)
{
	const char *classname;
	struct pfs_node *dir;
	struct device *dev;
	char charlink[16];	/* Major:Minor */

	classname = devclass_get_name(device_get_devclass(bsddev));

	if (strcmp(classname, DRM_DEV) == 0  &&
	    (dev = device_get_softc(bsddev)) != NULL) {
		dir = pfs_find_node(devdir, DRM_DEV);
		if (dir == NULL)
			dir = linsysfs_create_dir(devdir, DRM_DEV,
			    NULL, NULL, NULL);
		dir = linsysfs_create_dir(dir, dev_name(dev), NULL, NULL, NULL);
		linsysfs_create_file(dir, "uevent",
		    &linsysfs_drm_fill_uevent, NULL, NULL, NULL, PFS_RD, bsddev);
		linsysfs_create_link(dir, "device",
		    &linsysfs_drm_fill_vgapci, NULL, NULL, NULL, PFS_RD, devdir);
		linsysfs_create_link(dir, "subsystem",
		    &linsysfs_fill_data, NULL, NULL, NULL, PFS_RD,
		    "/sys/class/drm");
		snprintf(charlink, sizeof(charlink), "%d:%d",
		    MAJOR(dev->devt), MINOR(dev->devt));
		linsysfs_create_link(chardir, charlink,
		    &linsysfs_drm_fill_charlink, NULL, NULL, NULL, PFS_RD, dir);
		linsysfs_create_file(dir, "dev",
		    &linsysfs_drm_fill_dev, NULL, NULL, NULL, PFS_RD, bsddev);
		linsysfs_create_dir(dir, "power", NULL, NULL, NULL);
	}
}
