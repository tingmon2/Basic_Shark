#pragma once

// customize the auto alignment -> align struct member by 1 byte
// why? size of the stuct must be equal as Ethernet Header size. Otherwise, packet info we be tangled
#pragma pack(push, 1) 
typedef struct ether_header { 
	unsigned char dst[6];
	unsigned char src[6];
	unsigned short type; // ethernet header size 14 bytes
	// int nData;
} ether_header;
#pragma pack(pop)