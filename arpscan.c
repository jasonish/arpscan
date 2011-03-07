/*
 * $Id: arpscan.c,v 1.13 2009/07/07 20:59:48 jason Exp $
 *
 * Copyright (c) 2002-2005 Jason Ish <jason@codemonkey.net>
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include <pcap.h>
#ifdef DUMBNET
#include <dumbnet.h>
#else
#include <dnet.h>
#endif /* DUMBNET */

/* A concatenation of dnet's arp_hdr and arp_ethip. */
struct ether_arp {
	struct arp_hdr arp_hdr;
	struct arp_ethip arp_ethip;
};

extern char *__progname;
struct eth_hdr eth_header;
char pcap_errbuf[PCAP_ERRBUF_SIZE];
uint32_t my_ipaddr;
uint8_t my_ethaddr[6];

uint32_t ip_lo;
uint32_t ip_hi;

void
usage()
{
	fprintf(stderr, "USAGE: %s [-i interface] <ip-address>\n\n", 
	    __progname);
	fprintf(stderr, "\teg)\n");
	fprintf(stderr, "\t    %s 172.16.1.11\n", __progname);
	fprintf(stderr, "\t    %s 192.168.1.100-192.168.1.200\n", __progname);
	fprintf(stderr, "\t    %s 172.16.1.41/29\n");
	fprintf(stderr, "\n");
	exit(1);
}

/**
 * The libpcap callback when a packet has been received.  If its an
 * ARP reply, display it to stdout.
 */
void
pcap_cb(u_char *u, struct pcap_pkthdr *hdr, u_char *pkt)
{
	struct ether_arp *ether_arp;
	u_char eth_str[19];
	u_char ip_str[17];
	uint32_t ip;

	ether_arp = (struct ether_arp *)(pkt + sizeof(struct eth_hdr));

	/* We are only interested ARP replies. */
	if (ether_arp->arp_hdr.ar_op != ntohs(ARP_OP_REPLY))
		return;

	/* Don't display ARP replies that may have been caught that
	 * are out of our scan range. */
	ip = *(uint32_t *)ether_arp->arp_ethip.ar_spa;
	if (ip < ip_lo || ip > ip_hi)
		return;

	snprintf(eth_str, sizeof(eth_str) - 1, "%02x:%02x:%02x:%02x:%02x:%02x",
	    ether_arp->arp_ethip.ar_sha[0], ether_arp->arp_ethip.ar_sha[1],
	    ether_arp->arp_ethip.ar_sha[2], ether_arp->arp_ethip.ar_sha[3],
	    ether_arp->arp_ethip.ar_sha[4], ether_arp->arp_ethip.ar_sha[5]);

	snprintf(ip_str, sizeof(ip_str) - 1, "%d.%d.%d.%d",
	    ether_arp->arp_ethip.ar_spa[0], ether_arp->arp_ethip.ar_spa[1],
	    ether_arp->arp_ethip.ar_spa[2], ether_arp->arp_ethip.ar_spa[3]);

	printf("%-15s is at %s\n", ip_str, eth_str);
}

pcap_t *
init_pcap(char *dev_name)
{
	struct bpf_program bpf;
	pcap_t *pcap;
	int flags;
	char filter[1024];

	pcap = pcap_open_live(dev_name, 64, 1, 0, pcap_errbuf);
	if (pcap == NULL)
		errx(1, "error: %s\n", pcap_errbuf);

	/* Setup a pcap filter to catch only ARP replies destined for
	 * our MAC address. */
	snprintf(filter, sizeof(filter),
	    "arp and ether dst %02x:%02x:%02x:%02x:%02x:%02x",
	    my_ethaddr[0], my_ethaddr[1], my_ethaddr[2],
	    my_ethaddr[3], my_ethaddr[4], my_ethaddr[5]);
	if (pcap_compile(pcap, &bpf, filter, 1, 0) < 0) {
		pcap_close(pcap);
		errx(1, "failed to compile pcap filter");
	}
	if (pcap_setfilter(pcap, &bpf) < 0) {
		pcap_close(pcap);
		errx(1, "failed to set pcap filter");
	}

        /* Put pcap into non-blocking mode.  Some versions of pcap
         * have a handy pcap_setnonblock() functions, others don't.
	 */
        flags = fcntl(pcap_fileno(pcap), F_GETFL);
	flags |= O_NONBLOCK;
	if (fcntl(pcap_fileno(pcap), F_SETFL, flags) < 0)
	    warnx("failed to set pcap to non-blocking mode");
        
	return (pcap);
}

eth_t *
init_dnet(char *dev_name)
{
	intf_t *dnet_if;
	struct intf_entry entry;

	/* Use libdnet to get the IP and MAC address of the
	 * interface. */
	dnet_if = intf_open();
	memset(&entry, 0, sizeof(entry));
	strncpy(entry.intf_name, dev_name, INTF_NAME_LEN - 1);
	intf_get(dnet_if, &entry);
	memcpy(&my_ipaddr, &entry.intf_addr.addr_ip, sizeof(my_ipaddr));
	memcpy(&my_ethaddr, &entry.intf_link_addr.addr_eth,
	    sizeof(my_ethaddr));
	intf_close(dnet_if);

	/* Return a dnet ethernet object. */
	return eth_open(dev_name);
}

/**
 * Send an arp request.
 *
 * @param eth A pointer to a libdet ethernet handle.
 * @param ip The IP address to request an ARP reply from.
 */
void
send_arp(eth_t *eth, uint32_t ip)
{
	u_char pkt[sizeof(struct eth_hdr) + sizeof(struct ether_arp)];
	struct eth_hdr *ether;
	struct ether_arp *arp;
	char *buf;
	int rc;

	memset(pkt, 0, sizeof(pkt));

	memcpy(pkt, &eth_header, sizeof(eth_header));

	arp = (struct ether_arp *)(pkt + sizeof(struct eth_hdr));
	arp->arp_hdr.ar_hrd = htons(ARP_HRD_ETH);
	arp->arp_hdr.ar_pro = htons(ETH_TYPE_IP);
	arp->arp_hdr.ar_hln = ETH_ADDR_LEN;
	arp->arp_hdr.ar_pln = sizeof(ip);
	arp->arp_hdr.ar_op = htons(ARP_OP_REQUEST);

	memcpy(&arp->arp_ethip.ar_sha, &eth_header.eth_src,
	    sizeof(eth_header.eth_src));
	memcpy(&arp->arp_ethip.ar_spa, &my_ipaddr, sizeof(my_ipaddr));
	memcpy(&arp->arp_ethip.ar_tpa, &ip, sizeof(ip));

	eth_send(eth, (void *)pkt, sizeof(pkt));
}

int
main(int argc, char **argv)
{
	struct in_addr dummy_addr;
	char *cp, ch;
	char *dev_name = NULL;
	pcap_t *pcap;
	eth_t *dnet_eth;
	uint32_t cur_ip;
	int i;

	/* Parse command line options. */
	while ((ch = getopt(argc, argv, "i:")) != -1) {
		switch (ch) {
		case 'i':
			dev_name = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* Parse ip addresses. */
	if (argc < 1)
		usage();
	if ((cp = strchr(argv[0], '-')) != NULL) {
		*cp++ = '\0';
		ip_lo = inet_addr(argv[0]);
		if (ip_lo == INADDR_NONE) {
			warnx("invalid IP address: %s\n", argv[0]);
			usage();
		}
		ip_hi = inet_addr(cp);
		if (ip_hi == INADDR_NONE) {
			warnx("invalid IP address: %s\n", cp);
			usage();
		}
		if (ntohl(ip_lo) > ntohl(ip_hi)) {
			warnx("invalid address range: %s-%s\n",
			    argv[0], cp);
			usage();
		}
	} else if ((cp = strchr(argv[0], '/')) != NULL) {
		u_int32_t subnet;
		u_int32_t netmask;
		int bitmask;

		*cp++ = '\0';
		subnet = inet_addr(argv[0]);
		if (subnet == INADDR_NONE) {
			warnx("invalid subnet address: %s\n", argv[0]);
			usage();
		}
		subnet = ntohl(subnet);
		bitmask = atoi(cp);
		if (bitmask < 1 || bitmask > 32) {
			warnx("invalid netmask: %s\n", cp);
			usage();
		}
		netmask = 0xffffffff << (32 - bitmask);
		ip_lo = (htonl(subnet & netmask));
		ip_hi = htonl(subnet | ~netmask);
	} else {
		ip_lo = inet_addr(argv[0]);
		if (ip_lo == INADDR_NONE) {
			warnx("invalid IP address: %s\n", argv[0]);
			usage();
		}
		ip_hi = ip_lo;
	}

	/* If no interface name was provided, use the default returned
	 * by libpcap.
	 */
	if (dev_name == NULL) {
		dev_name = pcap_lookupdev(pcap_errbuf);
		if (dev_name == NULL)
			errx(1, "error: %s", pcap_errbuf);
		printf("Using interface %s.\n", dev_name);
	}

	/* Init. dnet. */
	dnet_eth = init_dnet(dev_name);
	if (dnet_eth == NULL)
		errx(1, "eth_open(%s) failed\n", dev_name);

	/* Init. pcap. init_pcap() will exit if an error occurs. */
	pcap = init_pcap(dev_name);

	/* Init. ethernet header. */
	memset(&eth_header.eth_dst, 0xff, sizeof(eth_header.eth_dst));
	memcpy(&eth_header.eth_src, my_ethaddr, sizeof(my_ethaddr));
	eth_header.eth_type = htons(ETH_TYPE_ARP);

	/* Main loop.
	 *
	 * Send arp request, check for any replies, send again.
	 */
	cur_ip = ip_lo;
	do {
		send_arp(dnet_eth, cur_ip);
		pcap_dispatch(pcap, -1, (void *)pcap_cb, NULL);
		cur_ip = htonl(ntohl(cur_ip) + 1);
	} while (ntohl(cur_ip) <= ntohl(ip_hi));

	/* Linger for ~5 seconds to pick up any late arrivals. */
	for (i = 0; i < 5; i++) {
		int x = 1;
		while (x > 0) {
			x = pcap_dispatch(pcap, -1, (void *)pcap_cb, NULL);
		}
		sleep(1);
	}

	eth_close(dnet_eth);
	pcap_close(pcap);

	return (0);
}
