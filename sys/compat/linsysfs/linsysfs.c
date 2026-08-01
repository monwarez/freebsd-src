/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2006 IronPort Systems
 * Copyright (c) 2023 Dmitry Chagin <dchagin@FreeBSD.org>
 * All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ctype.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/smp.h>
#include <sys/bus.h>
#include <sys/pciio.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <compat/linux/linux_util.h>
#include <fs/pseudofs/pseudofs.h>

#include <compat/linsysfs/linsysfs.h>

MALLOC_DEFINE(M_LINSYSFS, "linsysfs", "Linsysfs structures");

struct pci_nodes_queue {
	TAILQ_ENTRY(pci_nodes_queue) pci_nodes_next;
	device_t dev;
	struct pfs_node *node;;
 };
TAILQ_HEAD(,pci_nodes_queue) pci_nodes_q;

/* Mutex for pci_nodes_queue. */
static struct mtx pci_nodes_mtx;
MTX_SYSINIT(pci_nodes_mtx, &pci_nodes_mtx, "linsysfs", MTX_DEF);

/*
 * Create pci device node.
 */
static struct pfs_node *
linsysfs_create_pcidev_node(struct pfs_node *dir, struct pci_devinfo *dinfo,
    pfs_attr_t attr, pfs_vis_t vis, pfs_destroy_t destroy, int flags,
    device_t dev)
{
	char device[PCI_MAXNAMELEN + 1];
	struct pci_nodes_queue *nq;
	struct pfs_node *node;

	nq  = malloc(sizeof(*nq), M_LINSYSFS, M_WAITOK);

	sprintf(device, "0000:%02x:%02x.%x",
	    dinfo->cfg.bus,
	    dinfo->cfg.slot,
	    dinfo->cfg.func);
	pfs_create_dir(dir, &node, device, attr, vis, destroy, flags);
	node->pn_data = dev;
	nq->node = node;
	nq->dev= dev;
	mtx_lock(&pci_nodes_mtx);
	TAILQ_INSERT_TAIL(&pci_nodes_q, nq, pci_nodes_next);
	mtx_unlock(&pci_nodes_mtx);
	return (node);
}

/*
 * Locate a node by dev.
*/
struct pfs_node *
linsysfs_find_pcinode(device_t dev)
{
	struct pci_nodes_queue *nq, *nq_tmp;

	mtx_lock(&pci_nodes_mtx);
	TAILQ_FOREACH_SAFE(nq, &pci_nodes_q, pci_nodes_next, nq_tmp) {
		if (nq->dev == dev) {
			mtx_unlock(&pci_nodes_mtx);
			return (nq->node);
		}
	}
	mtx_unlock(&pci_nodes_mtx);
	return (NULL);
}

struct pfs_node *
linsysfs_create_dir(struct pfs_node *parent, const char *name,
    pfs_attr_t attr, pfs_vis_t vis, pfs_destroy_t destroy)
{
	struct pfs_node *node;

	if (parent == NULL)
		return (NULL);
	pfs_create_dir(parent, &node, name, attr, vis, destroy, 0);
	return (node);
}

struct pfs_node	*
linsysfs_create_file(struct pfs_node *parent, const char *name,
    pfs_fill_t fill, pfs_attr_t attr, pfs_vis_t vis, pfs_destroy_t destroy,
    int flags, void *data)
{
	struct pfs_node *node;

	pfs_create_file(parent, &node, name, fill, attr, vis, destroy, flags);
	node->pn_data = data;
	return (node);
}

struct pfs_node	*
linsysfs_create_link(struct pfs_node *parent, const char *name,
    pfs_fill_t fill, pfs_attr_t attr, pfs_vis_t vis, pfs_destroy_t destroy,
    int flags, void *data)
{
	struct pfs_node *node;

	pfs_create_link(parent, &node, name, fill, attr, vis, destroy, flags);
	node->pn_data = data;
	return (node);
}
/*
 * Filler function for proc_name
 */
static int
linsysfs_scsiname(PFS_FILL_ARGS)
{
	device_t dev = pn->pn_data;
	char *name;
	name = linux_driver_get_name_dev(dev);
	if (name != NULL)
		sbuf_printf(sb, "%s", name);
	else
		sbuf_printf(sb, "%s", device_get_nameunit(dev));
	return (0);
}

/*
 * Filler function for device sym-link
 */
static int
linsysfs_link_scsi_host(PFS_FILL_ARGS)
{
	struct pfs_node *node = pn->pn_data;
	char *path;

	path = linsysfs_full_pfs_path(node);
	sbuf_printf(sb, "../../../%s", path);
	free(path, M_TEMP);
	return (0);
}

int
linsysfs_fill_data(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "%s", (char *)pn->pn_data);
	return (0);
}

static int
linsysfs_fill_vendor(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "0x%04x\n", pci_get_vendor((device_t)pn->pn_data));
	return (0);
}

static int
linsysfs_fill_device(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "0x%04x\n", pci_get_device((device_t)pn->pn_data));
	return (0);
}

static int
linsysfs_fill_subvendor(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "0x%04x\n", pci_get_subvendor((device_t)pn->pn_data));
	return (0);
}

static int
linsysfs_fill_subdevice(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "0x%04x\n", pci_get_subdevice((device_t)pn->pn_data));
	return (0);
}

static int
linsysfs_fill_revid(PFS_FILL_ARGS)
{
	sbuf_printf(sb, "0x%x\n", pci_get_revid((device_t)pn->pn_data));
	return (0);
}

static int
linsysfs_fill_config(PFS_FILL_ARGS)
{
	uint8_t config[48];
	device_t dev;
	uint32_t reg;

	dev = (device_t)pn->pn_data;
	bzero(config, sizeof(config));
	reg = pci_get_vendor(dev);
	config[0] = reg;
	config[1] = reg >> 8;
	reg = pci_get_device(dev);
	config[2] = reg;
	config[3] = reg >> 8;
	reg = pci_get_revid(dev);
	config[8] = reg;
	reg = pci_get_subvendor(dev);
	config[44] = reg;
	config[45] = reg >> 8;
	reg = pci_get_subdevice(dev);
	config[46] = reg;
	config[47] = reg >> 8;
	sbuf_bcat(sb, config, sizeof(config));
	return (0);
}

/*
 * Filler function for PCI uevent file
 */
static int
linsysfs_fill_uevent_pci(PFS_FILL_ARGS)
{
	device_t dev;

	dev = (device_t)pn->pn_data;
	sbuf_printf(sb, "DRIVER=%s\nPCI_CLASS=%X\nPCI_ID=%04X:%04X\n"
	    "PCI_SUBSYS_ID=%04X:%04X\nPCI_SLOT_NAME=%04d:%02x:%02x.%x\n",
	    linux_driver_get_name_dev(dev), pci_get_class(dev),
	    pci_get_vendor(dev), pci_get_device(dev), pci_get_subvendor(dev),
	    pci_get_subdevice(dev), pci_get_domain(dev), pci_get_bus(dev),
	    pci_get_slot(dev), pci_get_function(dev));
	return (0);
}

char *
linsysfs_full_pfs_path(const struct pfs_node *cur)
{
	char *temp, *path;

	temp = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	path = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	path[0] = '\0';

	do {
		snprintf(temp, MAXPATHLEN, "%s/%s", cur->pn_name, path);
		strlcpy(path, temp, MAXPATHLEN);
		cur = cur->pn_parent;
	} while (cur->pn_parent != NULL);

	path[strlen(path) - 1] = '\0'; /* remove extra slash */
	free(temp, M_TEMP);
	return (path);
}

#undef PCI_DEV
#define PCI_DEV "pci"
#define DRMN_DEV "drmn"
/*
 * Filler callback for sys/devices/pci0000:00.
 */
static struct pfs_node *
linsysfs_pcibus_cb(device_t parent, device_t dev, struct pfs_node *pci,
    struct pfs_node *dir)
{
	struct pci_devinfo *dinfo;
	const char *classname;
	devclass_t dc;

	dinfo = NULL;
	classname = NULL;
	dc = device_get_devclass(parent);
	if (dc != NULL)
		classname = devclass_get_name(dc);
	if (strcmp(classname, PCI_DEV) == 0)
		dinfo = device_get_ivars(dev);

	/* PCI tree. */
	if (dinfo != NULL) {
		pci = linsysfs_create_pcidev_node(pci, dinfo,
		    NULL, NULL, NULL, 0, dev);
		linsysfs_create_file(pci, "vendor",
		    &linsysfs_fill_vendor, NULL, NULL, NULL, PFS_RD, dev);
		linsysfs_create_file(pci, "device",
		    &linsysfs_fill_device, NULL, NULL, NULL, PFS_RD, dev);
		linsysfs_create_file(pci, "subsystem_vendor",
		    &linsysfs_fill_subvendor, NULL, NULL, NULL, PFS_RD, dev);
		linsysfs_create_file(pci, "subsystem_device",
		    &linsysfs_fill_subdevice, NULL, NULL, NULL, PFS_RD, dev);
		linsysfs_create_file(pci, "revision",
		    &linsysfs_fill_revid, NULL, NULL, NULL, PFS_RD, dev);
		linsysfs_create_file(pci, "config",
		    &linsysfs_fill_config, NULL, NULL, NULL, PFS_RD, dev);
		linsysfs_create_file(pci, "uevent",
		    &linsysfs_fill_uevent_pci, NULL, NULL, NULL, PFS_RD, dev);
		linsysfs_create_link(pci, "subsystem",
		    &linsysfs_fill_data, NULL, NULL, NULL, 0, "/sys/bus/pci");
		/* TODO: libdrm just checks that the link ends in "/pci" */
	}
	/* vgapci/drmn childrens. */
	if (strcmp(classname, DRMN_DEV) == 0)
		linsysfs_bus_drm(pci, dir, dev);
	return (pci);
}

/*
 * Filler callback for scsi in sys/devices/pci0000:00.
 */
static struct pfs_node *
linsysfs_scsi_cb(device_t parent, device_t dev, struct pfs_node *pci,
    struct pfs_node *scsi)
{
	char host[PCI_MAXNAMELEN + 1];
	struct pci_devinfo *dinfo;
	const char *classname;
	struct pfs_node *pdir, *sdir;
	devclass_t dc;

	dinfo = NULL;
	classname = NULL;
	dc = device_get_devclass(parent);
	if (dc != NULL)
		classname = devclass_get_name(dc);
	if (strcmp(classname, PCI_DEV) == 0)
		dinfo = device_get_ivars(dev);

	if (dinfo != NULL &&
	    dinfo->cfg.baseclass == PCIC_STORAGE) {
		/* DJA only make this if needed */
		pdir = linsysfs_find_pcinode(dev);
		KASSERT(pdir != NULL, ("Inconsistent dev %p node", dev));
		if (pdir == NULL)
			return (pci);
		host[0] = '\000';
		snprintf(host, sizeof(host), "host%d",
		    device_get_unit(dev));
		sdir = linsysfs_create_dir(scsi, host, NULL, NULL, NULL);
		pdir = linsysfs_create_dir(pdir, host, NULL, NULL, NULL);
		linsysfs_create_link(sdir, "device",
		    &linsysfs_link_scsi_host, NULL, NULL, NULL, PFS_RD, pdir);
		linsysfs_create_file(sdir, "proc_name",
		    &linsysfs_scsiname, NULL, NULL, NULL, PFS_RD, dev);
	}
	return (pci);
}

/*
 * Traverse the device tree.
 */
static int
linsysfs_bus_foreach(device_t dev, linsysfs_bus_cb_t cb,
    struct pfs_node *pci, struct pfs_node *dir)
{
	device_t *ch, parent;
	int n, count, error;

	parent = device_get_parent(dev);
	if (parent != NULL)
		pci = (*cb)(parent, dev, pci, dir);
	error = device_get_children(dev, &ch, &count);
	if (error != 0)
		return (error);
	for (n = 0; n < count; n++) {
		error = linsysfs_bus_foreach(ch[n], cb, pci, dir);
		if (error != 0)
			break;
	}
	free(ch, M_TEMP);
	return (error);
}

/*
 * Scan device tree starting from root.
 */
static int
linsysfs_bus_scan(const char *root, linsysfs_bus_cb_t cb,
    struct pfs_node *pci, struct pfs_node *dir)
{
	devclass_t dc;
	device_t dev;
	int error;

	bus_topo_lock();
	dc = devclass_find(root);
	KASSERT(dc != NULL, ("Invalid %s class", root));
	dev = devclass_get_device(dc, 0);
	KASSERT(dev != NULL, ("Scan of %s failed", root));
	error = linsysfs_bus_foreach(dev, cb, pci, dir);
	bus_topo_unlock();
	return (error);
}

/*
 * Filler function for sys/devices/system/cpu/{online,possible,present}
 */
static int
linsysfs_cpuonline(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "%d-%d\n", CPU_FIRST(), mp_maxid);
	return (0);
}

/*
 * Filler function for sys/devices/system/cpu/cpuX/online
 */
static int
linsysfs_cpuxonline(PFS_FILL_ARGS)
{

	sbuf_printf(sb, "1\n");
	return (0);
}

static void
linsysfs_listcpus(struct pfs_node *dir)
{
	struct pfs_node *cpu;
	char *name;
	int i, count, len;

	len = 1;
	count = mp_maxcpus;
	while (count > 10) {
		count /= 10;
		len++;
	}
	len += sizeof("cpu");
	name = malloc(len, M_TEMP, M_WAITOK);

	for (i = 0; i < mp_ncpus; ++i) {
		/* /sys/devices/system/cpu/cpuX */
		sprintf(name, "cpu%d", i);
		pfs_create_dir(dir, &cpu, name, NULL, NULL, NULL, 0);

		pfs_create_file(cpu, NULL, "online", &linsysfs_cpuxonline, NULL,
		    NULL, NULL, PFS_RD);
	}
	free(name, M_TEMP);
}

/*
 * Constructor
 */
static int
linsysfs_init(PFS_INIT_ARGS)
{
	struct pfs_node *root;
	struct pfs_node *class;
	struct pfs_node *dir, *sys, *cpu;
	struct pfs_node *pci;
	struct pfs_node *scsi;
	struct pfs_node *devdir, *chardev;
	struct pfs_node *kernel;

	int error;
	TAILQ_INIT(&pci_nodes_q);
	root = pi->pi_root;

	/* /sys/bus/... */
	pfs_create_dir(root, &dir, "bus", NULL, NULL, NULL, 0);

	/* /sys/class/... */
	pfs_create_dir(root, &class, "class", NULL, NULL, NULL, 0);
	pfs_create_dir(class, &scsi, "scsi_host", NULL, NULL, NULL, 0);
	pfs_create_dir(class, NULL, "drm", NULL, NULL, NULL, 0);
	pfs_create_dir(class, NULL, "power_supply", NULL, NULL, NULL, 0);

	/* /sys/class/net/.. */
	pfs_create_dir(class, &net, "net", NULL, NULL, NULL, 0);

	/* /sys/dev/... */
	pfs_create_dir(root, &devdir, "dev", NULL, NULL, NULL, 0);
	pfs_create_dir(devdir, &chardev, "char", NULL, NULL, NULL, 0);

	/* /sys/devices/... */
	pfs_create_dir(root, &dir, "devices", NULL, NULL, NULL, 0);
	pfs_create_dir(dir, &pci, "pci0000:00", NULL, NULL, NULL, 0);

	/* /sys/devices/system */
	pfs_create_dir(dir, &sys, "system", NULL, NULL, NULL, 0);

	/* /sys/devices/system/cpu */
	pfs_create_dir(sys, &cpu, "cpu", NULL, NULL, NULL, 0);

	pfs_create_file(cpu, NULL, "online", &linsysfs_cpuonline, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(cpu, NULL, "possible", &linsysfs_cpuonline, NULL, NULL,
	    NULL, PFS_RD);
	pfs_create_file(cpu, NULL, "present", &linsysfs_cpuonline, NULL, NULL,
	    NULL, PFS_RD);

	linsysfs_listcpus(cpu);

	/* /sys/kernel */
	pfs_create_dir(root, &kernel, "kernel", NULL, NULL, NULL, 0);
	/* /sys/kernel/debug, mountpoint for lindebugfs. */
	pfs_create_dir(kernel, NULL, "debug", NULL, NULL, NULL, 0);

	linsysfs_net_init();

	/* /sys/devices/pci0000:00 */
	error = linsysfs_bus_scan("root", linsysfs_pcibus_cb, pci, chardev);
	if (error == 0)
		error = linsysfs_bus_scan("root", linsysfs_scsi_cb, pci, scsi);

	return (error);
}

/*
 * Destructor
 */
static int
linsysfs_uninit(PFS_INIT_ARGS)
{
	struct pci_nodes_queue *nq, *nq_tmp;
	mtx_lock(&pci_nodes_mtx);
	TAILQ_FOREACH_SAFE(nq, &pci_nodes_q, pci_nodes_next, nq_tmp) {
		TAILQ_REMOVE(&pci_nodes_q, nq, pci_nodes_next);
		free(nq, M_LINSYSFS);
	}
	mtx_unlock(&pci_nodes_mtx);
	linsysfs_net_uninit();

	return (0);
}

PSEUDOFS(linsysfs, 1, VFCF_JAIL);
#if defined(__aarch64__) || defined(__amd64__)
MODULE_DEPEND(linsysfs, linux_common, 1, 1, 1);
#else
MODULE_DEPEND(linsysfs, linux, 1, 1, 1);
#endif
