#pragma once
// customize the auto alignment -> align struct member by 1 byte
// why? size of the stuct must be equal as Ethernet Header size. Otherwise, packet info we be tangled
#pragma pack(push, 1) 
typedef struct payload {
	unsigned char version_ihl[1];
	unsigned char dscp_ecn[1];
	unsigned char length[2];
	unsigned char identification[2];
	unsigned char flag_offset[2];
	unsigned char ttl[1];
	unsigned char protocol[1];
	unsigned char checksum[2];
	unsigned char src_ip[4];
	unsigned char dst_ip[4];
} payload;
#pragma pack(pop)

#pragma pack(push, 1) 
typedef struct ether_header { 
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short type; // ethernet header size 14 bytes
} ether_header;
#pragma pack(pop)

#pragma pack(push, 1) 
typedef struct frame_data {
	struct ether_header;
	struct payload;
} frame_data;
#pragma pack(pop)

