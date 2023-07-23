#pragma once
// #pragma pack(push, 1) -> pre-processor customize the auto alignment -> align struct member by 1 byte
// why? size of the stuct must be equal as Ethernet Header size. Otherwise, packet info we be tangled
// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
#pragma pack(push, 1)
typedef struct tcp_header { 
	unsigned char src_port[2];
	unsigned char dst_port[2];
	unsigned char seq_num[4];
	unsigned char ack_num[4];
	unsigned char offset_reserved[1];
	unsigned char flag[1];
	unsigned char window_size[2];
	unsigned char checksum[2];
	unsigned char urgent_pointer[2];
} tcp_header;
#pragma pack(pop)

// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
#pragma pack(push, 1) 
typedef struct ip_header {
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
} ip_header;
#pragma pack(pop)

// https://en.wikipedia.org/wiki/EtherType
#pragma pack(push, 1) 
typedef struct ether_header { // frame header
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short type; // ethernet header size 14 bytes
} ether_header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct loop_header {
	unsigned char family[4];
} loop_header;
#pragma pack(pop)

#pragma pack(push, 1) 
typedef struct frame_data {
	struct ether_header;
	struct ip_header;
} frame_data;
#pragma pack(pop)

#pragma pack(push, 1) 
typedef struct loop_data {
	struct loop_header;
	struct ip_header;
} loop_data;
#pragma pack(pop)



