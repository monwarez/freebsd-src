.PATH: ${SRCTOP}/sys/compat/linsysfs

KMOD=	linsysfs
SRCS=	vnode_if.h \
	device_if.h bus_if.h  pci_if.h \
	linsysfs.c linsysfs_drm.c linsysfs_net.c
CFLAGS+= ${LINUXKPI_INCLUDES}

.if !defined(KERNBUILDDIR)
.warning Building Linuxulator outside of a kernel does not make sense
.endif

.include <bsd.kmod.mk>
