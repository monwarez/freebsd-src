/*-
 * Copyright (c) 2022 Soren Schmidt <sos@deepcore.dk>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/endian.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#include <dev/acpica/acpi_subr.h>

#include <dev/eqos/eqos_var.h>

static const struct acpi_compat_data compat_data[] = {
        {"snps,dwmac-4.20a",	1},
	{ NULL, 0 }
};


static int
eqos_acpi_probe(device_t dev)
{
	ACPI_HANDLE handle;
 
        if (!(handle = acpi_get_handle(dev)) || !acpi_MatchHid(handle, "PRP0001"))
                return (ENXIO);

	if (acpi_dsd_search_compatible(dev, compat_data)->acd_data == 0)	
		return ENXIO;

	device_set_desc(dev, "RK356x EQOS Gigabit ethernet");
	return BUS_PROBE_DEFAULT;
}


static device_method_t eqos_acpi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, eqos_acpi_probe),

	DEVMETHOD_END
};

DEFINE_CLASS_1(eqos, eqos_acpi_driver, eqos_acpi_methods,
    sizeof(struct eqos_softc), eqos_driver);

extern devclass_t eqos_devclass;

DRIVER_MODULE(eqos, acpi, eqos_acpi_driver, eqos_devclass, 0, 0);
MODULE_DEPEND(eqos, acpi, 1, 1, 1);
MODULE_DEPEND(eqos, ether, 1, 1, 1);
MODULE_DEPEND(eqos, miibus, 1, 1, 1);
