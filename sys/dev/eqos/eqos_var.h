/*-
 * Copyright (c) 2022 Jared McNeill <jmcneill@invisible.ca>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* $NetBSD: dwc_eqos_var.h,v 1.3 2022/01/09 00:36:28 mrg Exp $ */

/*
 * DesignWare Ethernet Quality-of-Service controller
 */

#ifndef _EQOS_VAR_H
#define _EQOS_VAR_H

#include <dev/eqos/eqos_reg.h>

#define	EQOS_DMA_DESC_COUNT	256

struct eqos_bufmap {
	bus_dmamap_t		map;
	struct mbuf		*mbuf;
};

struct eqos_ring {
	bus_dma_tag_t		desc_tag;
	bus_dmamap_t		desc_map;
	struct eqos_dma_desc	*desc_ring;
	bus_addr_t		desc_ring_paddr;

	bus_dma_tag_t		buf_tag;
	struct eqos_bufmap	buf_map[EQOS_DMA_DESC_COUNT];

	u_int			cur, next, queued;
};


#define	EQOS_RES_MEM		0
#define	EQOS_RES_IRQ0		1
#define	EQOS_RES_COUNT		2

#define EQOS_INTR_FLAGS		(INTR_TYPE_NET | INTR_MPSAFE)

struct eqos_softc {
	device_t		dev;
	struct resource 	*res[EQOS_RES_COUNT];
    	void            	*irq_handle;
        uint32_t        	csr_clock;
        uint32_t        	csr_clock_range;
	uint32_t		hw_feature[4];

	struct ifnet 		*ifp;
	device_t                miibus;
	struct callout		callout;
	struct mtx		lock;
	struct mtx		txlock;

	struct eqos_ring	tx;
	struct eqos_ring	rx;
};

DECLARE_CLASS(eqos_driver);

#endif
