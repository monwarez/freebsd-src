/*
 * Copyright 2022 Soren Schmidt <sos@deepcore.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/taskqueue.h>
#include <dev/mmc/bridge.h>
#ifdef FDT
#include <dev/mmc/mmc_fdt_helpers.h>
#endif
#include <dev/mmc/mmcreg.h>
#include <dev/mmc/host/dwmmc_var.h>
#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#include <dev/acpica/acpi_subr.h>

#include "opt_mmccam.h"

static const struct acpi_compat_data compat_data[] = {
	{"rockchip,rk3568-dw-mshc",	1},
	{"rockchip,rk3288-dw-mshc",	1},
	{NULL,				0},
};

static int
acpi_dwmmc_probe(device_t dev)
{
	ACPI_HANDLE handle;

        if (!(handle = acpi_get_handle(dev)) || !acpi_MatchHid(handle, "PRP0001"))
                return (ENXIO);

	if (!acpi_dsd_search_compatible(dev, compat_data)->acd_data)
                return ENXIO;

	device_set_desc(dev, "Synopsys DesignWare Mobile Storage Host Controller");
	return BUS_PROBE_VENDOR;
}

static int
acpi_dwmmc_attach(device_t dev)
{
	struct dwmmc_softc *sc = device_get_softc(dev);
	ACPI_HANDLE handle = acpi_get_handle(dev);
	ACPI_OBJECT *obj;
        ACPI_BUFFER buf;
        ACPI_STATUS status;

        /* Set some defaults for freq and supported mode */
	sc->hwtype = HWTYPE_ROCKCHIP;
        sc->host.caps = MMC_CAP_SIGNALING_330;
        sc->host.f_min = 400000;
        sc->host.f_max = 200000000;
        sc->host.host_ocr = MMC_OCR_320_330 | MMC_OCR_330_340;

	buf.Pointer = NULL;
        buf.Length = ACPI_ALLOCATE_BUFFER;
	status = acpi_dsd_property(handle, "bus-width", &buf, ACPI_TYPE_INTEGER, &obj);
	if (ACPI_SUCCESS(status)) {
		switch (obj->Integer.Value) {
		case 1:
			break;
		case 4:
			sc->host.caps |= MMC_CAP_4_BIT_DATA;
			break;
		case 8:
			sc->host.caps |= MMC_CAP_8_BIT_DATA;
			break;
		default:
			device_printf(dev, "Unsupported bus-width=%ld/n", obj->Integer.Value);
		}
	}
        if (buf.Pointer)
                AcpiOsFree(buf.Pointer);
	buf.Pointer = NULL;
        buf.Length = ACPI_ALLOCATE_BUFFER;
	status = acpi_dsd_property(handle, "fifo-depth", &buf, ACPI_TYPE_INTEGER, &obj);
	if (ACPI_SUCCESS(status))
		sc->fifo_depth = obj->Integer.Value;
        if (buf.Pointer)
                AcpiOsFree(buf.Pointer);
	buf.Pointer = NULL;
        buf.Length = ACPI_ALLOCATE_BUFFER;
	status = acpi_dsd_property(handle, "max-frequency", &buf, ACPI_TYPE_INTEGER, &obj);
	if (ACPI_SUCCESS(status))
		sc->bus_hz = obj->Integer.Value;
        if (buf.Pointer)
                AcpiOsFree(buf.Pointer);
	buf.Pointer = NULL;
        buf.Length = ACPI_ALLOCATE_BUFFER;
	status = acpi_dsd_property(handle, "cap-sd-highspeed", &buf, ACPI_TYPE_INTEGER, &obj);
	if (ACPI_SUCCESS(status))
		sc->host.caps |= MMC_CAP_HSPEED;
        if (buf.Pointer)
                AcpiOsFree(buf.Pointer);

	return (dwmmc_attach(dev));
}

static device_method_t acpi_dwmmc_methods[] = {
	/* bus interface */
	DEVMETHOD(device_probe, acpi_dwmmc_probe),
	DEVMETHOD(device_attach, acpi_dwmmc_attach),

	DEVMETHOD_END
};

static devclass_t acpi_dwmmc_devclass;

DEFINE_CLASS_1(acpi_dwmmc, acpi_dwmmc_driver, acpi_dwmmc_methods,
    sizeof(struct dwmmc_softc), dwmmc_driver);

DRIVER_MODULE(acpi_dwmmc, acpi, acpi_dwmmc_driver, acpi_dwmmc_devclass, 0, 0);
MODULE_DEPEND(acpi_dwmmc, acpi, 1, 1, 1);
#ifndef MMCCAM
MMC_DECLARE_BRIDGE(acpi_dwmmc);
#endif
