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
#include <math.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32")

char* switchProtocol(char protocol)
{
	switch ((int)protocol)
	{
	case 1:
		return "ICMP";
		break;
	case 2:
		return "IGMP";
		break;
	case 6:
		return "TCP";
		break;
	case 9:
		return "IGP";
		break;
	case 17:
		return "UDP";
		break;
	case 18:
		return "MUX";
		break;
	default:
		return "Other";
		break;
	}
}

BOOL isPshFlag(unsigned char tcp_flag)
{
	for (int i = 1; i < 8; i++)
	{
		char twopow = pow(2, i);
		switch (tcp_flag & twopow)
		{
		case ACK:
			break;
		case PSH:
			return TRUE;
			break;
		default:
			break;
		}
	}
}

int loopbackSniffer(tcp_header* tcpHeader)
{
	unsigned char protocol = readByte(tcpHeader->protocol[0]);
	if (protocol == 6)
	{
		int src_port = readShort(tcpHeader->src_port);
		int dst_port = readShort(tcpHeader->dst_port);
		unsigned char tcp_flag = readByte(*tcpHeader->tcp_flag);
		printf("src_port: %d, dst_port: %d, flag: %02X\n", src_port, dst_port, tcp_flag);
		printf("window_size: %d, checksum: %02X%02X, urgent_pointer: %d\n", 
			readShort(tcpHeader->window_size), 
			tcpHeader->tcp_checksum[0], tcpHeader->tcp_checksum[1], 
			readShort(tcpHeader->urgent_pointer));
		printf("sequence_number: %d\n\n", readInt(tcpHeader->seq_num));
		if (src_port == 25000 || dst_port == 25000)
		{
			// only flag PSH
			if (isPshFlag(tcp_flag))
			{
				if (src_port != 25000)
				{
					printf("from client: ");
				}
				else // src_port == 25000
				{
					printf("from server: ");
				}
				for (int i = 0; i < 10; i++)
				{
					if (*(tcpHeader->startOfTheEnd + i) == 0) // end of message
					{
						printf("\n\n");
						break;
					}
					else
					{
						printf("%c", *(tcpHeader->startOfTheEnd + i));

					}
				}
			}
		}
	}
	return 0;
}

int generalSensor(frame_data* pFrame)
{
	if (pFrame->type == (short)0x0008) // 0x0800 - Internet Protocol version 4 (IPv4)
	{
		printf("src MAC: %02X-%02X-%02X-%02X-%02X-%02X -> dst MAC: %02X-%02X-%02X-%02X-%02X-%02X (type: %04X)\n",
			pFrame->src_mac[0], pFrame->src_mac[1], pFrame->src_mac[2], pFrame->src_mac[3],
			pFrame->src_mac[4], pFrame->src_mac[5],
			pFrame->dst_mac[0], pFrame->dst_mac[1], pFrame->dst_mac[2], pFrame->dst_mac[3],
			pFrame->dst_mac[4], pFrame->dst_mac[5],
			pFrame->type);

		// ip version and protocol
		unsigned char version_ihl = readByte(*pFrame->version_ihl);
		unsigned char protocol = readByte(*pFrame->protocol);
		char* strBuffer[10] = { 0 };
		strcpy_s(strBuffer, sizeof(strBuffer), switchProtocol(protocol));
		printf("version: %X, ihl: %X, protocol: %d(%s)\n", version_ihl >> 4, version_ihl & 0x0F, protocol, strBuffer);

		// pakcet size
		short packet_size = readShort(pFrame->length);
		printf("packet size: %d bytes\n", packet_size);

		// ip address
		printf("src IP: %d.%d.%d.%d -> dst IP: %d.%d.%d.%d\n\n",
			pFrame->src_ip[0], pFrame->src_ip[1], pFrame->src_ip[2], pFrame->src_ip[3],
			pFrame->dst_ip[0], pFrame->dst_ip[1], pFrame->dst_ip[2], pFrame->dst_ip[3]);
	}
	return 0;
}

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
	
	if (header->len < 14) // it can't be and shouldn't be happen
		return;
	int isLoopback = readInt(pkt_data);
	if (isLoopback == 33554432) // loopback - sniff my message!
	{
		tcp_header* tcpHeader = (tcp_header*)pkt_data;
		loopbackSniffer(tcpHeader);
	}
	else
	{
		frame_data* pFrame = (frame_data*)pkt_data;
		generalSensor(pFrame);
	}
}
