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
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/malloc.h>

#include <contrib/dev/acpica/include/acpi.h>

#include <dev/acpica/acpivar.h>

#include "acpi_subr.h"

static MALLOC_DEFINE(M_ACPISUBR, "acpisubr", "ACPI subrutines");

static const uint8_t dsd_uuid[] = {
        0x14, 0xd8, 0xff, 0xda, 0xba, 0x6e, 0x8c, 0x4d,
        0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a, 0xa3, 0x01,
};


ACPI_STATUS
acpi_dsd_property(ACPI_HANDLE handle, const char *property, ACPI_BUFFER *buf, ACPI_OBJECT_TYPE type, ACPI_OBJECT **ret)
{
        ACPI_OBJECT *prop, *obj, *pobj;
        ACPI_STATUS status;
        int i;

        status = AcpiEvaluateObjectTyped(handle, "_DSD", NULL, buf, ACPI_TYPE_PACKAGE);
        if (ACPI_FAILURE(status))
                return status;

        prop = NULL;
        obj = (ACPI_OBJECT *)buf->Pointer;
        for (i = 0; i < (obj->Package.Count - 1); i += 2) {
                if (obj->Package.Elements[i].Buffer.Length == ACPI_UUID_LENGTH &&
                    !bcmp(dsd_uuid, obj->Package.Elements[i].Buffer.Pointer, ACPI_UUID_LENGTH)) {
                        prop = &obj->Package.Elements[i + 1];
                        break;
                }
        }
        if (!prop)
                return AE_NOT_FOUND;

        for (i = 0; i < prop->Package.Count; i++) {
                pobj = &prop->Package.Elements[i];
                if (pobj->Type != ACPI_TYPE_PACKAGE || pobj->Package.Count != 2)
                        continue;
                if (pobj->Package.Elements[0].Type != ACPI_TYPE_STRING)
                        continue;
                if (strcmp(pobj->Package.Elements[0].String.Pointer, property))
                        continue;

                if (pobj->Package.Elements[1].Type == type) {
                        *ret = &pobj->Package.Elements[1];
                        return AE_OK;
                }
		else 
                        return AE_TYPE;
                break;
        }
        return AE_NOT_FOUND;
}

const struct acpi_compat_data *
acpi_dsd_search_compatible(device_t dev, const struct acpi_compat_data *compat)
{
	const struct acpi_compat_data *pcompat = NULL;
	ACPI_HANDLE handle = acpi_get_handle(dev);
        ACPI_OBJECT *obj;
	ACPI_BUFFER buf;
        ACPI_STATUS status;
        int i;

        buf.Pointer = NULL;
        buf.Length = ACPI_ALLOCATE_BUFFER;
       
	/* single string _DSD */
	status = acpi_dsd_property(handle, "compatible", &buf, ACPI_TYPE_STRING, &obj);
        if (ACPI_SUCCESS(status)) {
		for (pcompat = compat; pcompat->acd_str; pcompat++)
                	if (!strcmp(obj->String.Pointer, pcompat->acd_str))
				break;
		goto done;
        }

       	if (buf.Pointer)
               	AcpiOsFree(buf.Pointer);
        buf.Pointer = NULL;
        buf.Length = ACPI_ALLOCATE_BUFFER;

        /* Package of strings _DSD */
        status = acpi_dsd_property(handle, "compatible", &buf, ACPI_TYPE_PACKAGE, &obj);
        if (ACPI_FAILURE(status)) {
                goto done;
        }
        if (!obj->Package.Count) {
                goto done;
        }
        for (i = 0; i < obj->Package.Count; i++) {
                if (obj->Package.Elements[i].Type != ACPI_TYPE_STRING)
                        continue;
		for (pcompat = compat; pcompat->acd_str; pcompat++)
			if (!strcmp(obj->Package.Elements[i].String.Pointer, pcompat->acd_str))
				break;
		if (pcompat->acd_str)
			break;
        }
done:
        if (buf.Pointer)
                AcpiOsFree(buf.Pointer);
        return pcompat;
}
