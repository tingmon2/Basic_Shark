#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <tchar.h>

#include "basic_shark.h"
#include "decoder.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32")

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
	pcap_if_t* alldevs; // all network devices single list
	pcap_if_t* d; // the device
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32 // conditional compliation with FLAG(_WIN32)
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous) - read all act like a sniffer
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	// printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
	if (header->len < 14) // it can't be and shouldn't be happen
		return;
	frame_data* pFrame = (frame_data*)pkt_data;
	// print hex value MAC address
	// https://en.wikipedia.org/wiki/EtherType
	if (pFrame->type == (short)0x0008) // 0x0800 - Internet Protocol version 4 (IPv4)
	{
		printf("src MAC: %02X-%02X-%02X-%02X-%02X-%02X -> dst MAC: %02X-%02X-%02X-%02X-%02X-%02X (type: %04X)\n",
			pFrame->src_mac[0], pFrame->src_mac[1], pFrame->src_mac[2], pFrame->src_mac[3],
			pFrame->src_mac[4], pFrame->src_mac[5],
			pFrame->dst_mac[0], pFrame->dst_mac[1], pFrame->dst_mac[2], pFrame->dst_mac[3],
			pFrame->dst_mac[4], pFrame->dst_mac[5],
			pFrame->type);

		// print IP address
		// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
		// skip 64 bit of ipv4 header
		char buf[INET_ADDRSTRLEN], buf6[INET6_ADDRSTRLEN];
		//printf("src IP: %s ->", inet_ntop(AF_INET, (IN_ADDR*)(pkt_data + sizeof(ether_header) + 12), buf, sizeof(buf)));
		//printf(" dst IP: %s\n\n", inet_ntop(AF_INET, (IN_ADDR*)(pkt_data + sizeof(ether_header) + 16), buf, sizeof(buf)));
		unsigned char version_ihl = pFrame->version_ihl[0];
		//unsigned char ihl = version_ihl & 0x0F; // 0000 0101
		//unsigned char version = version_ihl & 0xF0; //  0100 0000
		//printf("version: %X, ihl: %X\n", version>>4, ihl);
		printf("version: %X, ihl: %X\n", version_ihl >> 4, version_ihl & 0x0F);
		short packet_size = readShort(pFrame->length);
		printf("packet size: %d bytes\n", packet_size);
		printf("src IP: %d.%d.%d.%d -> dst IP: %d.%d.%d.%d\n\n",
			pFrame->src_ip[0], pFrame->src_ip[1], pFrame->src_ip[2], pFrame->src_ip[3],
			pFrame->dst_ip[0], pFrame->dst_ip[1], pFrame->dst_ip[2], pFrame->dst_ip[3]);
	}
}
