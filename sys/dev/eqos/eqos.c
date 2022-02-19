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
/* $NetBSD: dwc_eqos.c,v 1.3 2022/01/09 00:36:28 mrg Exp $ */

/*
 * DesignWare Ethernet Quality-of-Service controller
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <sys/endian.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/systm.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/bpf.h>

#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>

#include <dev/eqos/eqos_reg.h>
#include <dev/eqos/eqos_var.h>

#include "miibus_if.h"

#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#include <dev/acpica/acpi_subr.h>


#define DESC_BOUNDARY           (1ULL << 32)
#define	DESC_ALIGN		sizeof(struct eqos_dma_desc)
#define	TX_DESC_COUNT		EQOS_DMA_DESC_COUNT
#define	TX_DESC_SIZE		(TX_DESC_COUNT * DESC_ALIGN)
#define	RX_DESC_COUNT		EQOS_DMA_DESC_COUNT
#define	RX_DESC_SIZE		(RX_DESC_COUNT * DESC_ALIGN)
#define	DESC_OFF(n)		((n) * sizeof(struct eqos_dma_desc))
#define	TX_SKIP(n, o)		(((n) + (o)) % TX_DESC_COUNT)
#define	TX_NEXT(n)		TX_SKIP(n, 1)
#define	RX_NEXT(n)		(((n) + 1) % RX_DESC_COUNT)
#define	TX_MAX_SEGS		128
#define	MII_BUSY_RETRY		1000

#define	EQOS_LOCK(sc)			mtx_lock(&(sc)->lock)
#define	EQOS_UNLOCK(sc)			mtx_unlock(&(sc)->lock)
#define	EQOS_ASSERT_LOCKED(sc)		mtx_assert(&(sc)->lock, MA_OWNED)

#define	EQOS_TXLOCK(sc)			mtx_lock(&(sc)->txlock)
#define	EQOS_TXUNLOCK(sc)		mtx_unlock(&(sc)->txlock)
#define	EQOS_ASSERT_TXLOCKED(sc)	mtx_assert(&(sc)->txlock, MA_OWNED)

#define	RD4(sc, offset)			\
	bus_read_4(sc->res[EQOS_RES_MEM], (offset))
#define	WR4(sc, offset, val)		\
	bus_write_4(sc->res[EQOS_RES_MEM], (offset), (val))


static struct resource_spec eqos_spec[] = {
        { SYS_RES_MEMORY,       0,      RF_ACTIVE },
        { SYS_RES_IRQ,          0,      RF_ACTIVE },
        { -1, 0 }
};


static int
eqos_miibus_readreg(device_t dev, int phy, int reg)
{
	struct eqos_softc *sc = device_get_softc(dev);
	uint32_t addr;
	int retry, val;

	addr = sc->csr_clock_range |
	    (phy << GMAC_MAC_MDIO_ADDRESS_PA_SHIFT) | (reg << GMAC_MAC_MDIO_ADDRESS_RDA_SHIFT) |
	    GMAC_MAC_MDIO_ADDRESS_GOC_READ | GMAC_MAC_MDIO_ADDRESS_GB;
	WR4(sc, GMAC_MAC_MDIO_ADDRESS, addr);

	DELAY(100);

	for (retry = MII_BUSY_RETRY; retry > 0; retry--) {
		addr = RD4(sc, GMAC_MAC_MDIO_ADDRESS);
		if (!(addr & GMAC_MAC_MDIO_ADDRESS_GB)) {
			val = RD4(sc, GMAC_MAC_MDIO_DATA) & 0xFFFF;
			break;
		}
		DELAY(10);
	}
	if (!retry) {
		device_printf(dev, "phy read timeout, phy=%d reg=%d\n", phy, reg);
		return ETIMEDOUT;
	}

	return val;
}

static int
eqos_miibus_writereg(device_t dev, int phy, int reg, int val)
{
	struct eqos_softc *sc = device_get_softc(dev);
	uint32_t addr;
	int retry;

	WR4(sc, GMAC_MAC_MDIO_DATA, val);

	addr = sc->csr_clock_range |
	    (phy << GMAC_MAC_MDIO_ADDRESS_PA_SHIFT) | (reg << GMAC_MAC_MDIO_ADDRESS_RDA_SHIFT) |
	    GMAC_MAC_MDIO_ADDRESS_GOC_WRITE | GMAC_MAC_MDIO_ADDRESS_GB;
	WR4(sc, GMAC_MAC_MDIO_ADDRESS, addr);

	DELAY(100);

	for (retry = MII_BUSY_RETRY; retry > 0; retry--) {
		addr = RD4(sc, GMAC_MAC_MDIO_ADDRESS);
		if (!(addr & GMAC_MAC_MDIO_ADDRESS_GB)) {
			break;
		}
		DELAY(10);
	}
	if (!retry) {
		device_printf(dev, "phy write timeout, phy=%d reg=%d\n", phy, reg);
		return ETIMEDOUT;
	}

	return 0;
}

static void
eqos_miibus_statchg(device_t dev)
{
	struct eqos_softc *sc = device_get_softc(dev);
	struct mii_data *mii = device_get_softc(sc->miibus);
	uint32_t reg;

	EQOS_ASSERT_LOCKED(sc);

	reg = RD4(sc, GMAC_MAC_CONFIGURATION);

	switch (IFM_SUBTYPE(mii->mii_media_active)) {
	case IFM_10_T:
		reg |= GMAC_MAC_CONFIGURATION_PS;
		reg &= ~GMAC_MAC_CONFIGURATION_FES;
		break;
	case IFM_100_TX:
		reg |= GMAC_MAC_CONFIGURATION_PS;
		reg |= GMAC_MAC_CONFIGURATION_FES;
		break;
	case IFM_1000_T:
        case IFM_1000_SX:
		reg &= ~GMAC_MAC_CONFIGURATION_PS;
		reg &= ~GMAC_MAC_CONFIGURATION_FES;
		break;
	case IFM_2500_T:
	case IFM_2500_SX:
		reg &= ~GMAC_MAC_CONFIGURATION_PS;
		reg |= GMAC_MAC_CONFIGURATION_FES;
		break;
	default:
                return;
	}

	if ((IFM_OPTIONS(mii->mii_media_active) & IFM_FDX))
		reg |= GMAC_MAC_CONFIGURATION_DM;
	else 
		reg &= ~GMAC_MAC_CONFIGURATION_DM;

	WR4(sc, GMAC_MAC_CONFIGURATION, reg);
}

static void
eqos_media_status(struct ifnet * ifp, struct ifmediareq *ifmr)
{
        struct eqos_softc *sc = ifp->if_softc;
        struct mii_data *mii = device_get_softc(sc->miibus);

	EQOS_LOCK(sc);
        mii_pollstat(mii);
        ifmr->ifm_active = mii->mii_media_active;
        ifmr->ifm_status = mii->mii_media_status;
        EQOS_UNLOCK(sc);
}

static int
eqos_media_change(struct ifnet * ifp)
{
        struct eqos_softc *sc = ifp->if_softc;
        int error;

        EQOS_LOCK(sc);
        error = mii_mediachg(device_get_softc(sc->miibus)); 
        EQOS_UNLOCK(sc);
        return (error);
}

static void
eqos_setup_txdesc(struct eqos_softc *sc, int index, int flags,
    bus_addr_t paddr, u_int len, u_int total_len)
{
	uint32_t tdes2, tdes3;

	if (!paddr || !len) {
		tdes2 = 0;
		tdes3 = 0;
		if (--sc->tx.queued < 0)
			printf("ERROR: tx.queued less than 0\n");
	} else {
		tdes2 = (flags & EQOS_TDES3_LD) ? EQOS_TDES2_IOC : 0;
		tdes3 = flags;
		if (++sc->tx.queued >= TX_DESC_COUNT - 1)
			printf("ERROR: tx.queued bigger than %d\n", TX_DESC_COUNT);
	}

	sc->tx.desc_ring[index].tdes0 = htole32((uint32_t)paddr);
	sc->tx.desc_ring[index].tdes1 = htole32((uint32_t)(paddr >> 32));
	sc->tx.desc_ring[index].tdes2 = htole32(tdes2 | len);
	sc->tx.desc_ring[index].tdes3 = htole32(tdes3 | total_len);
}

static int
eqos_setup_txbuf(struct eqos_softc *sc, int index, struct mbuf *m)
{
	bus_dma_segment_t segs[TX_MAX_SEGS];
	int error, nsegs, cur, i;
	uint32_t flags;

	error = bus_dmamap_load_mbuf_sg(sc->tx.buf_tag, sc->tx.buf_map[index].map, m, segs, &nsegs, 0);
	if (error == EFBIG) {
		device_printf(sc->dev, "TX packet needs too many DMA segments\n");
		return -2;
	}
	if (error) {
		device_printf(sc->dev, "TX packet could not be mapped\n");
		return 0;
	}

	if (sc->tx.queued + nsegs > TX_DESC_COUNT) {
		bus_dmamap_unload(sc->tx.buf_tag, sc->tx.buf_map[index].map);
		device_printf(sc->dev, "TX packet no more queue space\n");
		return -1;
	}

	bus_dmamap_sync(sc->tx.buf_tag, sc->tx.buf_map[index].map, BUS_DMASYNC_PREWRITE);    

	sc->tx.buf_map[index].mbuf = m;

	for (flags = EQOS_TDES3_FD, cur = index, i = 0; i < nsegs; i++) {
		if (i == (nsegs - 1))
			flags |= EQOS_TDES3_LD;
		eqos_setup_txdesc(sc, cur, flags, segs[i].ds_addr, segs[i].ds_len, m->m_pkthdr.len);
		flags &= ~EQOS_TDES3_FD;
		flags |= EQOS_TDES3_OWN;
		cur = TX_NEXT(cur);
	}

	/* Defer setting OWN bit on the first descriptor until all descriptors have been updated */
	wmb();
	sc->tx.desc_ring[index].tdes3 |= htole32(EQOS_TDES3_OWN);
	wmb();

	return nsegs;
}

static void
eqos_setup_rxdesc(struct eqos_softc *sc, int index, bus_addr_t paddr)
{
	sc->rx.desc_ring[index].tdes0 = htole32((uint32_t)paddr);
	sc->rx.desc_ring[index].tdes1 = htole32((uint32_t)(paddr >> 32));
	sc->rx.desc_ring[index].tdes2 = htole32(0);
	wmb();
	sc->rx.desc_ring[index].tdes3 = htole32(EQOS_TDES3_OWN | EQOS_TDES3_IOC | EQOS_TDES3_BUF1V);
	wmb();
}

static int
eqos_setup_rxbuf(struct eqos_softc *sc, int index, struct mbuf *m)
{
	struct bus_dma_segment seg;
        int error, nsegs;

	m_adj(m, ETHER_ALIGN);

	error = bus_dmamap_load_mbuf_sg(sc->rx.buf_tag, sc->rx.buf_map[index].map, m, &seg, &nsegs, 0);
	if (error)
		return error;

	KASSERT(nsegs == 1, ("%s: %d segments returned!", __func__, nsegs));

	bus_dmamap_sync(sc->rx.buf_tag, sc->rx.buf_map[index].map, BUS_DMASYNC_PREREAD);

	sc->rx.buf_map[index].mbuf = m;
	eqos_setup_rxdesc(sc, index, seg.ds_addr);

	return 0;
}

static struct mbuf *
eqos_alloc_mbufcl(struct eqos_softc *sc)
{
	struct mbuf *m;

	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m != NULL)
		m->m_pkthdr.len = m->m_len = m->m_ext.ext_size;
	return m;
}

static void
eqos_enable_intr(struct eqos_softc *sc)
{
	WR4(sc, GMAC_DMA_CHAN0_INTR_ENABLE,
	    GMAC_DMA_CHAN0_INTR_ENABLE_NIE | GMAC_DMA_CHAN0_INTR_ENABLE_AIE |
	    GMAC_DMA_CHAN0_INTR_ENABLE_FBE | GMAC_DMA_CHAN0_INTR_ENABLE_RIE |
	    GMAC_DMA_CHAN0_INTR_ENABLE_TIE);
}

static void
eqos_disable_intr(struct eqos_softc *sc)
{
	WR4(sc, GMAC_DMA_CHAN0_INTR_ENABLE, 0);
}

static void
eqos_tick(void *softc)
{
	struct eqos_softc *sc = softc;
	struct mii_data *mii = device_get_softc(sc->miibus);

	mii_tick(mii);
	callout_reset(&sc->callout, hz, eqos_tick, sc);
}

static uint32_t
eqos_bitrev32(uint32_t x)
{
        x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
        x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
        x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
        x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
        return (x >> 16) | (x << 16);
}

static u_int
eqos_hash_maddr(void *arg, struct sockaddr_dl *sdl, u_int cnt)
{
        uint32_t crc, *hash = arg;
                 
        crc = ether_crc32_le(LLADDR(sdl), ETHER_ADDR_LEN);
	crc &= 0x7f;
	crc = eqos_bitrev32(~crc) >> 26;
        hash[crc >> 5] |= 1 << (crc & 0x1f);
        return 1;
}

static void
eqos_setup_rxfilter(struct eqos_softc *sc)
{
	struct ifnet *ifp = sc->ifp;
	uint32_t pfil, hash[2]; 
	const uint8_t *eaddr;
	uint32_t val;

	EQOS_ASSERT_LOCKED(sc);

	pfil = RD4(sc, GMAC_MAC_PACKET_FILTER);
	pfil &= ~(GMAC_MAC_PACKET_FILTER_PR |
		  GMAC_MAC_PACKET_FILTER_PM |
		  GMAC_MAC_PACKET_FILTER_HMC |
		  GMAC_MAC_PACKET_FILTER_PCF_MASK);
	hash[0] = hash[1] = 0xffffffff;

	if ((ifp->if_flags & IFF_PROMISC)) {
		pfil |= GMAC_MAC_PACKET_FILTER_PR |
			GMAC_MAC_PACKET_FILTER_PCF_ALL;
	} else if ((ifp->if_flags & IFF_ALLMULTI)) {
		pfil |= GMAC_MAC_PACKET_FILTER_PM;
	} else {
		hash[0] = hash[1] = 0;
		pfil |= GMAC_MAC_PACKET_FILTER_HMC;
		if_foreach_llmaddr(ifp, eqos_hash_maddr, hash);
	}

	/* Write our unicast address */
	eaddr = IF_LLADDR(ifp);
	val = eaddr[4] | (eaddr[5] << 8);
	WR4(sc, GMAC_MAC_ADDRESS0_HIGH, val);
	val = eaddr[0] | (eaddr[1] << 8) | (eaddr[2] << 16) |
	    (eaddr[3] << 24);
	WR4(sc, GMAC_MAC_ADDRESS0_LOW, val);

	/* Multicast hash filters */
	WR4(sc, GMAC_MAC_HASH_TABLE_REG0, hash[1]);
	WR4(sc, GMAC_MAC_HASH_TABLE_REG1, hash[0]);

	/* Packet filter config */
	WR4(sc, GMAC_MAC_PACKET_FILTER, pfil);
}

static int
eqos_reset(struct eqos_softc *sc)
{
	uint32_t val;
	int retry;

	WR4(sc, GMAC_DMA_MODE, GMAC_DMA_MODE_SWR);
	for (retry = 2000; retry > 0; retry--) {
		DELAY(1000);
		val = RD4(sc, GMAC_DMA_MODE);
		if (!(val & GMAC_DMA_MODE_SWR))
			return 0;
	}
	return ETIMEDOUT;
}

static void
eqos_init_rings(struct eqos_softc *sc, int qid)
{
	sc->tx.queued = 0;

	WR4(sc, GMAC_DMA_CHAN0_TX_BASE_ADDR_HI,
	    (uint32_t)(sc->tx.desc_ring_paddr >> 32));
	WR4(sc, GMAC_DMA_CHAN0_TX_BASE_ADDR,
	    (uint32_t)sc->tx.desc_ring_paddr);
	WR4(sc, GMAC_DMA_CHAN0_TX_RING_LEN, TX_DESC_COUNT - 1);

	WR4(sc, GMAC_DMA_CHAN0_RX_BASE_ADDR_HI,
	    (uint32_t)(sc->rx.desc_ring_paddr >> 32));
	WR4(sc, GMAC_DMA_CHAN0_RX_BASE_ADDR,
	    (uint32_t)sc->rx.desc_ring_paddr);
	WR4(sc, GMAC_DMA_CHAN0_RX_RING_LEN, RX_DESC_COUNT - 1);

	WR4(sc, GMAC_DMA_CHAN0_RX_END_ADDR,
	    (uint32_t)sc->rx.desc_ring_paddr + DESC_OFF((sc->rx.cur - 1) % RX_DESC_COUNT));
}

static void
eqos_init(void *if_softc)
{
	struct eqos_softc *sc = if_softc;
	struct ifnet *ifp = sc->ifp;
	struct mii_data *mii = device_get_softc(sc->miibus);
	uint32_t val;

	if (if_getdrvflags(ifp) & IFF_DRV_RUNNING)
		return;

	EQOS_LOCK(sc);
	EQOS_TXLOCK(sc);

	/* Setup TX/RX rings */
	eqos_init_rings(sc, 0);

	/* Setup RX filter */
	eqos_setup_rxfilter(sc);

	WR4(sc, GMAC_MAC_1US_TIC_COUNTER, (sc->csr_clock / 1000000) - 1);

	/* Enable transmit and receive DMA */
	val = RD4(sc, GMAC_DMA_CHAN0_CONTROL);
	val &= ~GMAC_DMA_CHAN0_CONTROL_DSL_MASK;
	val |= ((DESC_ALIGN - 16) / 8) << GMAC_DMA_CHAN0_CONTROL_DSL_SHIFT;
	val |= GMAC_DMA_CHAN0_CONTROL_PBLX8;
	WR4(sc, GMAC_DMA_CHAN0_CONTROL, val);
	val = RD4(sc, GMAC_DMA_CHAN0_TX_CONTROL);
	val |= GMAC_DMA_CHAN0_TX_CONTROL_OSP;
	val |= GMAC_DMA_CHAN0_TX_CONTROL_START;
	WR4(sc, GMAC_DMA_CHAN0_TX_CONTROL, val);
	val = RD4(sc, GMAC_DMA_CHAN0_RX_CONTROL);
	val &= ~GMAC_DMA_CHAN0_RX_CONTROL_RBSZ_MASK;
	val |= (MCLBYTES << GMAC_DMA_CHAN0_RX_CONTROL_RBSZ_SHIFT);
	val |= GMAC_DMA_CHAN0_RX_CONTROL_START;
	WR4(sc, GMAC_DMA_CHAN0_RX_CONTROL, val);

	/* Configure operation modes */
	WR4(sc, GMAC_MTL_TXQ0_OPERATION_MODE,
	    GMAC_MTL_TXQ0_OPERATION_MODE_TSF |
	    GMAC_MTL_TXQ0_OPERATION_MODE_TXQEN_EN);
	WR4(sc, GMAC_MTL_RXQ0_OPERATION_MODE,
	    GMAC_MTL_RXQ0_OPERATION_MODE_RSF |
	    GMAC_MTL_RXQ0_OPERATION_MODE_FEP |
	    GMAC_MTL_RXQ0_OPERATION_MODE_FUP);

	/* Enable flow control */
	val = RD4(sc, GMAC_MAC_Q0_TX_FLOW_CTRL);
	val |= 0xFFFFU << GMAC_MAC_Q0_TX_FLOW_CTRL_PT_SHIFT;
	val |= GMAC_MAC_Q0_TX_FLOW_CTRL_TFE;
	WR4(sc, GMAC_MAC_Q0_TX_FLOW_CTRL, val);
	val = RD4(sc, GMAC_MAC_RX_FLOW_CTRL);
	val |= GMAC_MAC_RX_FLOW_CTRL_RFE;
	WR4(sc, GMAC_MAC_RX_FLOW_CTRL, val);

	/* Enable transmitter and receiver */
	val = RD4(sc, GMAC_MAC_CONFIGURATION);
	val |= GMAC_MAC_CONFIGURATION_BE;
	val |= GMAC_MAC_CONFIGURATION_JD;
	val |= GMAC_MAC_CONFIGURATION_JE;
	val |= GMAC_MAC_CONFIGURATION_DCRS;
	val |= GMAC_MAC_CONFIGURATION_TE;
	val |= GMAC_MAC_CONFIGURATION_RE;
	WR4(sc, GMAC_MAC_CONFIGURATION, val);

	/* Enable interrupts */
	eqos_enable_intr(sc);

	if_setdrvflagbits(ifp, IFF_DRV_RUNNING, IFF_DRV_OACTIVE);

	mii_mediachg(mii);
	callout_reset(&sc->callout, hz, eqos_tick, sc);

	EQOS_TXUNLOCK(sc);
	EQOS_UNLOCK(sc);
}

static void
eqos_stop(struct eqos_softc *sc)
{
	struct ifnet *ifp = sc->ifp;
        uint32_t val;

        EQOS_LOCK(sc);

        if_setdrvflagbits(ifp, 0, IFF_DRV_RUNNING | IFF_DRV_OACTIVE);

        callout_stop(&sc->callout);

        /* Disable receiver */
        val = RD4(sc, GMAC_MAC_CONFIGURATION);
        val &= ~GMAC_MAC_CONFIGURATION_RE;
        WR4(sc, GMAC_MAC_CONFIGURATION, val);

        /* Stop receive DMA */
        val = RD4(sc, GMAC_DMA_CHAN0_RX_CONTROL);
        val &= ~GMAC_DMA_CHAN0_RX_CONTROL_START;
        WR4(sc, GMAC_DMA_CHAN0_RX_CONTROL, val);

        /* Stop transmit DMA */
        val = RD4(sc, GMAC_DMA_CHAN0_TX_CONTROL);
        val &= ~GMAC_DMA_CHAN0_TX_CONTROL_START;
        WR4(sc, GMAC_DMA_CHAN0_TX_CONTROL, val);

#if 0
        if (disable) {
        	int retry;

                /* Flush data in the TX FIFO */
                val = RD4(sc, GMAC_MTL_TXQ0_OPERATION_MODE);
                val |= GMAC_MTL_TXQ0_OPERATION_MODE_FTQ;
                WR4(sc, GMAC_MTL_TXQ0_OPERATION_MODE, val);
                /* Wait for flush to complete */
                for (retry = 10000; retry > 0; retry--) {
                        val = RD4(sc, GMAC_MTL_TXQ0_OPERATION_MODE);
                        if (!(val & GMAC_MTL_TXQ0_OPERATION_MODE_FTQ)) {
                                break;
                        }
                        delay(1);
                }
                if (!retry) {
                        device_printf(sc->sc_dev, "timeout flushing TX queue\n");
                }
        }
#endif
        /* Disable transmitter */
        val = RD4(sc, GMAC_MAC_CONFIGURATION);
        val &= ~GMAC_MAC_CONFIGURATION_TE;
        WR4(sc, GMAC_MAC_CONFIGURATION, val);

        /* Disable interrupts */
        eqos_disable_intr(sc);

	EQOS_UNLOCK(sc);
}

static void
eqos_rxintr(struct eqos_softc *sc, int qid)
{
	struct ifnet *ifp = sc->ifp;
	int error, index, len, pkts = 0;
	struct mbuf *m, *m0;
	uint32_t tdes3;

	for (index = sc->rx.cur; ; index = RX_NEXT(index)) {
		tdes3 = le32toh(sc->rx.desc_ring[index].tdes3);
		if ((tdes3 & EQOS_TDES3_OWN))
			break;

		bus_dmamap_sync(sc->rx.buf_tag, sc->rx.buf_map[index].map, BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(sc->rx.buf_tag, sc->rx.buf_map[index].map);

		len = tdes3 & EQOS_TDES3_LENGTH_MASK;
		if (len) {
			m = sc->rx.buf_map[index].mbuf;
			m->m_pkthdr.rcvif = ifp;
			m->m_pkthdr.len = len;
			// XXX SOS m->m_flags |= M_HASFCS;
			m->m_len = len;
			m->m_nextpkt = NULL;

			/* Remove trailing FCS */
        		m_adj(m, -ETHER_CRC_LEN);

			EQOS_UNLOCK(sc);
		        (*ifp->if_input)(ifp, m);
        		EQOS_LOCK(sc);

			++pkts;
		}

		if ((m0 = eqos_alloc_mbufcl(sc))) {
			if ((error = eqos_setup_rxbuf(sc, index, m0))) {
				printf("ERROR: Hole in RX ring!!\n");
			}
		} else {
			// SOS XXX if_statinc(ifp, if_ierrors);
		}

		WR4(sc, GMAC_DMA_CHAN0_RX_END_ADDR,
		    (uint32_t)sc->rx.desc_ring_paddr + DESC_OFF(sc->rx.cur));
	}

	sc->rx.cur = index;
#if 0
	if (pkts) {
		rnd_add_uint32(&sc->sc_rndsource, pkts);
	}
#endif
}

static void
eqos_txintr(struct eqos_softc *sc, int qid)
{
	struct ifnet *ifp = sc->ifp;
	struct eqos_bufmap *bmap;
	struct eqos_dma_desc *desc;
	uint32_t tdes3;
	int i, pkts = 0;

	EQOS_ASSERT_LOCKED(sc);

	for (i = sc->tx.next; sc->tx.queued > 0; i = TX_NEXT(i)) {
		desc = &sc->tx.desc_ring[i];
		tdes3 = le32toh(desc->tdes3);
		if ((tdes3 & EQOS_TDES3_OWN))
			break;

		bmap = &sc->tx.buf_map[i];
		if (bmap->mbuf != NULL) {
			bus_dmamap_sync(sc->tx.buf_tag, bmap->map, BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(sc->tx.buf_tag, bmap->map);
			m_freem(bmap->mbuf);
			bmap->mbuf = NULL;
			++pkts;
		}

		eqos_setup_txdesc(sc, i, 0, 0, 0, 0);

		if_setdrvflagbits(ifp, 0, IFF_DRV_OACTIVE);

		/* Last descriptor in a packet contains DMA status */
		if ((tdes3 & EQOS_TDES3_LD)) {
			if ((tdes3 & EQOS_TDES3_DE)) {
				device_printf(sc->dev, "TX [%u] desc error: 0x%08x\n", i, tdes3);
				// SOS XXX if_statinc(ifp, if_oerrors);
			} else if ((tdes3 & EQOS_TDES3_ES)) {
				device_printf(sc->dev, "TX [%u] tx error: 0x%08x\n", i, tdes3);
				// SOS XXX if_statinc(ifp, if_oerrors);
			} else {
				// SOS XXX if_statinc(ifp, if_opackets);
			}
		}
	}

	sc->tx.next = i;
#if 0
	if (pkts) {
		rnd_add_uint32(&sc->sc_rndsource, pkts);
	}
#endif
}

static void
eqos_start(struct ifnet *ifp)
{
	struct eqos_softc *sc = ifp->if_softc;
	struct mbuf *m;
	int cnt, start, nsegs;


	if ((if_getdrvflags(ifp) & (IFF_DRV_RUNNING|IFF_DRV_OACTIVE)) != IFF_DRV_RUNNING)
                return;

	EQOS_TXLOCK(sc);

	for (cnt = 0, start = sc->tx.cur; ; cnt++) {
		if (sc->tx.queued >= TX_DESC_COUNT - TX_MAX_SEGS) {
			if_setdrvflagbits(ifp, IFF_DRV_OACTIVE, 0);
			break;
		}

		IFQ_POLL(&ifp->if_snd, m);
		if (!m)
			break;

		nsegs = eqos_setup_txbuf(sc, sc->tx.cur, m);
		if (nsegs <= 0) {
			if (nsegs == -1) {
				if_setdrvflagbits(ifp, IFF_DRV_OACTIVE, 0);
			} else {
				if (nsegs == -2) {
					IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
					m_freem(m);
				}
			}
			break;
		}

		IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
		ETHER_BPF_MTAP(ifp, m);

		sc->tx.cur = TX_SKIP(sc->tx.cur, nsegs);
	}

	if (cnt) {
		/* Start and run TX DMA */
		WR4(sc, GMAC_DMA_CHAN0_TX_END_ADDR,
		    (uint32_t)sc->tx.desc_ring_paddr + DESC_OFF(sc->tx.cur));
	}

	EQOS_TXUNLOCK(sc);
}

static void
eqos_intr_mtl(struct eqos_softc *sc, uint32_t mtl_status)
{
	uint32_t debug_data __unused = 0, ictrl = 0;

	if ((mtl_status & GMAC_MTL_INTERRUPT_STATUS_DBGIS)) {
		debug_data = RD4(sc, GMAC_MTL_FIFO_DEBUG_DATA);
	}
	if ((mtl_status & GMAC_MTL_INTERRUPT_STATUS_Q0IS)) {
		uint32_t new_status = 0;

		ictrl = RD4(sc, GMAC_MTL_Q0_INTERRUPT_CTRL_STATUS);
		if ((ictrl & GMAC_MTL_Q0_INTERRUPT_CTRL_STATUS_RXOVFIS)) {
			new_status |= GMAC_MTL_Q0_INTERRUPT_CTRL_STATUS_RXOVFIS;
		}
		if ((ictrl & GMAC_MTL_Q0_INTERRUPT_CTRL_STATUS_TXUNFIS)) {
			new_status |= GMAC_MTL_Q0_INTERRUPT_CTRL_STATUS_TXUNFIS;
		}
		if (new_status) {
			new_status |= (ictrl &
			    (GMAC_MTL_Q0_INTERRUPT_CTRL_STATUS_RXOIE|
			     GMAC_MTL_Q0_INTERRUPT_CTRL_STATUS_TXUIE));
			WR4(sc, GMAC_MTL_Q0_INTERRUPT_CTRL_STATUS, new_status);
		}
	}
#if 1
	device_printf(sc->dev,
	    "GMAC_MTL_INTERRUPT_STATUS = 0x%08X, "
	    "GMAC_MTL_FIFO_DEBUG_DATA = 0x%08X, "
	    "GMAC_MTL_INTERRUPT_STATUS_Q0IS = 0x%08X\n",
	    mtl_status, debug_data, ictrl);
#endif
}

static void
eqos_intr(void *arg)
{
	struct eqos_softc *sc = arg;
	uint32_t mac_status, mtl_status, dma_status, rx_tx_status;

	mac_status = RD4(sc, GMAC_MAC_INTERRUPT_STATUS);
	mac_status &= RD4(sc, GMAC_MAC_INTERRUPT_ENABLE);

	if (mac_status) {
		// update event counter
	}

	if ((mtl_status = RD4(sc, GMAC_MTL_INTERRUPT_STATUS)))
		eqos_intr_mtl(sc, mtl_status);

	dma_status = RD4(sc, GMAC_DMA_CHAN0_STATUS);
	dma_status &= RD4(sc, GMAC_DMA_CHAN0_INTR_ENABLE);

	if (dma_status)
		WR4(sc, GMAC_DMA_CHAN0_STATUS, dma_status);

	EQOS_LOCK(sc);
	if ((dma_status & GMAC_DMA_CHAN0_STATUS_RI)) {
		// update rx irq counter
		eqos_rxintr(sc, 0);
	}

	if ((dma_status & GMAC_DMA_CHAN0_STATUS_TI)) {
		// update tx irq counter
		eqos_txintr(sc, 0);
	}
	EQOS_UNLOCK(sc);

	if (!(mac_status | mtl_status | dma_status)) {
		device_printf(sc->dev, "spurious interrupt?!\n");
	}

	rx_tx_status = RD4(sc, GMAC_MAC_RX_TX_STATUS);
	if (rx_tx_status) {
		// update diverse event counts
	}
}

static int
eqos_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct eqos_softc *sc = ifp->if_softc;
        struct ifreq *ifr = (struct ifreq *)data;
        struct mii_data *mii;
        int flags, mask;
	int error = 0;

        switch (cmd) {
        case SIOCSIFFLAGS:
                if (if_getflags(ifp) & IFF_UP) {
                        if (if_getdrvflags(ifp) & IFF_DRV_RUNNING) {
                                flags = if_getflags(ifp); // SOS XXX ^ sc->if_flags;
                                if ((flags & (IFF_PROMISC|IFF_ALLMULTI))) {
                			EQOS_LOCK(sc);
                                        eqos_setup_rxfilter(sc);
					EQOS_UNLOCK(sc);
				}
                        } else {
                                // SOS XXX if (!sc->is_detaching)
                                eqos_init(sc);
                        }
                } else {
                        if (if_getdrvflags(ifp) & IFF_DRV_RUNNING)
                                eqos_stop(sc);
                }
                // SOS XXX sc->if_flags = if_getflags(ifp);
                break;

        case SIOCADDMULTI:
        case SIOCDELMULTI:
                if (if_getdrvflags(ifp) & IFF_DRV_RUNNING) {
                        EQOS_LOCK(sc);
                        eqos_setup_rxfilter(sc);
                        EQOS_UNLOCK(sc);
                }
                break;

        case SIOCSIFMEDIA:
        case SIOCGIFMEDIA:
		mii = device_get_softc(sc->miibus);
                error = ifmedia_ioctl(ifp, ifr, &mii->mii_media, cmd);
                break;

        case SIOCSIFCAP:
                mask = ifr->ifr_reqcap ^ if_getcapenable(ifp);
                if (mask & IFCAP_VLAN_MTU)
                        if_togglecapenable(ifp, IFCAP_VLAN_MTU);
                if (mask & IFCAP_RXCSUM)
                        if_togglecapenable(ifp, IFCAP_RXCSUM);
                if (mask & IFCAP_TXCSUM)
                        if_togglecapenable(ifp, IFCAP_TXCSUM);
                if ((if_getcapenable(ifp) & IFCAP_TXCSUM))
                        if_sethwassistbits(ifp, CSUM_IP | CSUM_UDP | CSUM_TCP, 0);
                else
                        if_sethwassistbits(ifp, 0, CSUM_IP | CSUM_UDP | CSUM_TCP);
                break;

        default:
                error = ether_ioctl(ifp, cmd, data);
                break;
        }

	return error;
}

static void
eqos_get_eaddr(struct eqos_softc *sc, uint8_t *eaddr)
{
	uint32_t maclo, machi, rnd;

	maclo = htobe32(RD4(sc, GMAC_MAC_ADDRESS0_LOW));
	machi = htobe16(RD4(sc, GMAC_MAC_ADDRESS0_HIGH) & 0xFFFF);

	if (maclo == 0xffffffff && machi == 0xffff) {
		rnd = arc4random() & 0x00ffffff;
                eaddr[0] = 'b';
                eaddr[1] = 's';
                eaddr[2] = 'd';
                eaddr[3] = rnd >> 16;
                eaddr[4] = rnd >>  8;
                eaddr[5] = rnd >>  0;
	}
	else {
		eaddr[0] = maclo & 0xff;
		eaddr[1] = (maclo >> 8) & 0xff;
		eaddr[2] = (maclo >> 16) & 0xff;
		eaddr[3] = (maclo >> 24) & 0xff;
		eaddr[4] = machi & 0xff;
		eaddr[5] = (machi >> 8) & 0xff;
	}
}

static void
eqos_axi_configure(struct eqos_softc *sc)
{
	uint32_t val;

	val = RD4(sc, GMAC_DMA_SYSBUS_MODE);
#if 0
	if (prop_dictionary_get_bool(prop, "snps,mixed-burst", &bval) && bval) {
		val |= GMAC_DMA_SYSBUS_MODE_MB;
	}
	if (prop_dictionary_get_bool(prop, "snps,fixed-burst", &bval) && bval) {
		val |= GMAC_DMA_SYSBUS_MODE_FB;
	}
	if (prop_dictionary_get_uint(prop, "snps,wr_osr_lmt", &uival)) {
		val &= ~GMAC_DMA_SYSBUS_MODE_WR_OSR_LMT_MASK;
		val |= uival << GMAC_DMA_SYSBUS_MODE_WR_OSR_LMT_SHIFT;
	}
	if (prop_dictionary_get_uint(prop, "snps,rd_osr_lmt", &uival)) {
		val &= ~GMAC_DMA_SYSBUS_MODE_RD_OSR_LMT_MASK;
		val |= uival << GMAC_DMA_SYSBUS_MODE_RD_OSR_LMT_SHIFT;
	}
#else
	/* defaults */
	val |= GMAC_DMA_SYSBUS_MODE_MB;
	val &= ~GMAC_DMA_SYSBUS_MODE_WR_OSR_LMT_MASK;
        val |= 0x03 << GMAC_DMA_SYSBUS_MODE_WR_OSR_LMT_SHIFT;
	val &= ~GMAC_DMA_SYSBUS_MODE_RD_OSR_LMT_MASK;
	val |= 0x07 << GMAC_DMA_SYSBUS_MODE_RD_OSR_LMT_SHIFT;
#endif

	// SOS XXX 32bit only not this val |= GMAC_DMA_SYSBUS_MODE_EAME;
	val |= GMAC_DMA_SYSBUS_MODE_BLEN16;
	val |= GMAC_DMA_SYSBUS_MODE_BLEN8;
	val |= GMAC_DMA_SYSBUS_MODE_BLEN4;

	WR4(sc, GMAC_DMA_SYSBUS_MODE, val);
}

static void
eqos_get1paddr(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
        if (error)
                return;
        *(bus_addr_t *)arg = segs[0].ds_addr;
}

static int
eqos_setup_dma(struct eqos_softc *sc, int qid)
{
	struct mbuf *m;
	int error, i;

	/* Set up TX descriptor ring, descriptors, and dma maps */
        error = bus_dma_tag_create(
            bus_get_dma_tag(sc->dev),  	/* Parent tag. */
            DESC_ALIGN, DESC_BOUNDARY, 	/* alignment, boundary */
            BUS_SPACE_MAXADDR_32BIT,    /* lowaddr */
            BUS_SPACE_MAXADDR,          /* highaddr */
            NULL, NULL,                 /* filter, filterarg */
            TX_DESC_SIZE, 1,            /* maxsize, nsegments */
            TX_DESC_SIZE,               /* maxsegsize */
            0,                          /* flags */
            NULL, NULL,                 /* lockfunc, lockarg */
            &sc->tx.desc_tag);
        if (error) {
                device_printf(sc->dev, "could not create TX ring DMA tag.\n");
                return error;
        }

        error = bus_dmamem_alloc(sc->tx.desc_tag, (void**)&sc->tx.desc_ring,
            BUS_DMA_COHERENT | BUS_DMA_WAITOK | BUS_DMA_ZERO,
            &sc->tx.desc_map);
        if (error) {
                device_printf(sc->dev, "could not allocate TX descriptor ring.\n");
                return error;
        }

        error = bus_dmamap_load(sc->tx.desc_tag, sc->tx.desc_map,
            sc->tx.desc_ring, TX_DESC_SIZE, eqos_get1paddr,
            &sc->tx.desc_ring_paddr, 0);
        if (error) {
                device_printf(sc->dev, "could not load TX descriptor ring map.\n");
                return error;
        }

	error = bus_dma_tag_create(
            bus_get_dma_tag(sc->dev),   /* Parent tag. */
            1, 0,                       /* alignment, boundary */
            BUS_SPACE_MAXADDR_32BIT,    /* lowaddr */
            BUS_SPACE_MAXADDR,          /* highaddr */
            NULL, NULL,                 /* filter, filterarg */
            MCLBYTES*TX_MAX_SEGS,   	/* maxsize */
            TX_MAX_SEGS,            	/* nsegments */
            MCLBYTES,                   /* maxsegsize */
            0,                          /* flags */
            NULL, NULL,                 /* lockfunc, lockarg */
            &sc->tx.buf_tag);
        if (error) {
                device_printf(sc->dev, "could not create TX buffer DMA tag.\n");
                return error;
        }

	sc->tx.queued = TX_DESC_COUNT;
	for (i = 0; i < TX_DESC_COUNT; i++) {
		error = bus_dmamap_create(sc->tx.buf_tag, BUS_DMA_COHERENT,
		    &sc->tx.buf_map[i].map);
		if (error) {
			device_printf(sc->dev, "cannot create TX buffer map\n");
			return error;
		}
		eqos_setup_txdesc(sc, i, 0, 0, 0, 0);
	}

	/* Set up RX descriptor ring, descriptors, dma maps, and mbufs */
        error = bus_dma_tag_create(
            bus_get_dma_tag(sc->dev),   /* Parent tag. */
            DESC_ALIGN, DESC_BOUNDARY,	/* alignment, boundary */
            BUS_SPACE_MAXADDR_32BIT,    /* lowaddr */
            BUS_SPACE_MAXADDR,          /* highaddr */
            NULL, NULL,                 /* filter, filterarg */
            RX_DESC_SIZE, 1,            /* maxsize, nsegments */
            RX_DESC_SIZE,               /* maxsegsize */
            0,                          /* flags */
            NULL, NULL,                 /* lockfunc, lockarg */
            &sc->rx.desc_tag);
        if (error) {
                device_printf(sc->dev, "could not create RX ring DMA tag.\n");
                return error;
        }

        error = bus_dmamem_alloc(sc->rx.desc_tag, (void **)&sc->rx.desc_ring,
            BUS_DMA_COHERENT | BUS_DMA_WAITOK | BUS_DMA_ZERO,
            &sc->rx.desc_map);
        if (error) {
                device_printf(sc->dev, "could not allocate RX descriptor ring.\n");
                return error;
        }
            
        error = bus_dmamap_load(sc->rx.desc_tag, sc->rx.desc_map,
            sc->rx.desc_ring, RX_DESC_SIZE, eqos_get1paddr,
            &sc->rx.desc_ring_paddr, 0);
        if (error) {
                device_printf(sc->dev, "could not load RX descriptor ring map.\n");
                return error;
        }

	error = bus_dma_tag_create(
            bus_get_dma_tag(sc->dev),   /* Parent tag. */
            1, 0,                       /* alignment, boundary */
            BUS_SPACE_MAXADDR_32BIT,    /* lowaddr */
            BUS_SPACE_MAXADDR,          /* highaddr */
            NULL, NULL,                 /* filter, filterarg */
            MCLBYTES, 1,                /* maxsize, nsegments */
            MCLBYTES,                   /* maxsegsize */
            0,                          /* flags */
            NULL, NULL,                 /* lockfunc, lockarg */
            &sc->rx.buf_tag);
        if (error) {
                device_printf(sc->dev, "could not create RX buf DMA tag.\n");
                return error;
        }

	for (i = 0; i < RX_DESC_COUNT; i++) {
		error = bus_dmamap_create(sc->rx.buf_tag, BUS_DMA_COHERENT,
		    &sc->rx.buf_map[i].map);
		if (error) {
			device_printf(sc->dev, "cannot create RX buffer map\n");
			return error;
		}
		if (!(m = eqos_alloc_mbufcl(sc))) {
			device_printf(sc->dev, "cannot allocate RX mbuf\n");
			return ENOMEM;
		}
		error = eqos_setup_rxbuf(sc, i, m);
		if (error) {
			device_printf(sc->dev, "cannot create RX buffer\n");
			return error;
		}
	}

	if (bootverbose)
		device_printf(sc->dev, "TX ring @ 0x%lx, RX ring @ 0x%lx\n",
	    	    sc->tx.desc_ring_paddr, sc->rx.desc_ring_paddr);

	return 0;
}

static int
eqos_attach(device_t dev)
{
	struct eqos_softc *sc = device_get_softc(dev);
	struct ifnet *ifp; 
	uint32_t ver;
	uint8_t eaddr[ETHER_ADDR_LEN];
	u_int userver, snpsver;
	int error;
	int n;

        /* setup resources */
        if (bus_alloc_resources(dev, eqos_spec, sc->res)) {
                device_printf(dev, "Could not allocate resources\n");
                bus_release_resources(dev, eqos_spec, sc->res);
                return ENXIO;
        }
 
        sc->dev = dev;
        sc->csr_clock = 125000000;      // SOS XXX CSR_RATE_RGMII;
	sc->csr_clock_range = GMAC_MAC_MDIO_ADDRESS_CR_100_150;

	ver  = RD4(sc, GMAC_MAC_VERSION);
	userver = (ver & GMAC_MAC_VERSION_USERVER_MASK) >> GMAC_MAC_VERSION_USERVER_SHIFT;
	snpsver = ver & GMAC_MAC_VERSION_SNPSVER_MASK;

	if (snpsver != 0x51) {
		device_printf(sc->dev, "EQOS version 0x%02xx not supported\n", snpsver);
		return ENXIO;
	}

	for (n = 0; n < 4; n++)
		sc->hw_feature[n] = RD4(sc, GMAC_MAC_HW_FEATURE(n));

	if (bootverbose) {
		device_printf(sc->dev, "DesignWare EQOS ver 0x%02x (0x%02x)\n", snpsver, userver);
		device_printf(sc->dev, "hw features %08x %08x %08x %08x\n",
		    sc->hw_feature[0], sc->hw_feature[1], sc->hw_feature[2], sc->hw_feature[3]);
	}

	mtx_init(&sc->lock, "eqos lock", MTX_NETWORK_LOCK, MTX_DEF);
	mtx_init(&sc->txlock, "eqos txlock", MTX_NETWORK_LOCK, MTX_DEF);

	callout_init_mtx(&sc->callout, &sc->lock, 0);

	eqos_get_eaddr(sc, eaddr);
	if (bootverbose)
		device_printf(sc->dev, "Ethernet address %6D\n", eaddr, ":");

	/* Soft reset EMAC core */
	if ((error = eqos_reset(sc))) {
		device_printf(sc->dev, "reset timeout!\n");
		return error;
	}

	/* Configure AXI Bus mode parameters */
	eqos_axi_configure(sc);

	/* Setup DMA descriptors */
	if (eqos_setup_dma(sc, 0)) {
		device_printf(sc->dev, "failed to setup DMA descriptors\n");
		return EINVAL;
	}

	/* setup interrupt delivery */
        if ((bus_setup_intr(dev, sc->res[EQOS_RES_IRQ0], EQOS_INTR_FLAGS, NULL, eqos_intr, sc, &sc->irq_handle))) {
                device_printf(dev, "unable to setup 1st interrupt\n");
                bus_release_resources(dev, eqos_spec, sc->res);
                return ENXIO;
        }

	/* Setup ethernet interface */
	ifp = sc->ifp = if_alloc(IFT_ETHER);
	ifp->if_softc = sc;
	if_initname(ifp, device_get_name(sc->dev), device_get_unit(sc->dev));
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_start = eqos_start;
	ifp->if_ioctl = eqos_ioctl;
	ifp->if_init = eqos_init;
	if_setsendqlen(ifp, TX_DESC_COUNT - 1);
        if_setsendqready(ifp);
        if_setcapabilities(ifp, IFCAP_VLAN_MTU | IFCAP_HWCSUM);
        if_setcapenable(ifp, if_getcapabilities(ifp));

	if ((error = mii_attach(sc->dev, &sc->miibus, ifp, eqos_media_change,
            			eqos_media_status, BMSR_DEFCAPMASK, MII_PHY_ANY,
            			MII_OFFSET_ANY, 0))) {
                device_printf(sc->dev, "PHY attach failed\n");
                return (ENXIO);
        }

	/* Attach ethernet interface */
	ether_ifattach(ifp, eaddr);

	return 0;
}

static int
eqos_detach(device_t dev)
{
        struct eqos_softc *sc = device_get_softc(dev);

        if (sc->irq_handle)
                bus_teardown_intr(dev, sc->res[EQOS_RES_IRQ0], sc->irq_handle);
	// SOS XX free BUSDMA resources
        bus_release_resources(dev, eqos_spec, sc->res);
        return 0;
}


static device_method_t eqos_methods[] = {
        DEVMETHOD(device_attach,        eqos_attach),
        DEVMETHOD(device_detach,        eqos_detach),
                
        /* MII Interface */
        DEVMETHOD(miibus_readreg,       eqos_miibus_readreg),
        DEVMETHOD(miibus_writereg,      eqos_miibus_writereg),
        DEVMETHOD(miibus_statchg,       eqos_miibus_statchg),
        
        DEVMETHOD_END
};
        
driver_t eqos_driver = {
        "eqos",
        eqos_methods,
        sizeof(struct eqos_softc),
};
        
devclass_t eqos_devclass;
        
DRIVER_MODULE(miibus, eqos, miibus_driver, miibus_devclass, 0, 0);
