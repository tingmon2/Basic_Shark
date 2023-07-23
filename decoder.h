#pragma once

typedef enum TCP_FLAG {
	CONGESTION_WINDOW = 128,
	ECN_ECHO = 64,
	URGENT = 32,
	ACK = 16,
	PSH = 8,
	RST = 4,
	SYN = 2,
	FIN = 1 
} TCP_FLAG;

int readByte(unsigned char* data)
{
	return (int)data & 0xFF;
}
short readShort(unsigned char* data)
{
	int byte1 = readByte(data[0]);
	int byte2 = readByte(data[1]);
	return (unsigned short) (byte1 << 8) + byte2;
}

int readInt(unsigned char* data)
{
	int byte1 = readByte(data[0]); 
	int byte2 = readByte(data[1]); 
	int byte3 = readByte(data[2]); 
	int byte4 = readByte(data[3]); 
	return (unsigned int) (byte1 << 24) + (byte2 << 16) + (byte3 << 8) + byte4;
}

long readLong(unsigned char* data)
{
	long byte1 = readByte(data[0]);
	long byte2 = readByte(data[1]);
	long byte3 = readByte(data[2]);
	long byte4 = readByte(data[3]);
	long byte5 = readByte(data[4]);
	long byte6 = readByte(data[5]);
	long byte7 = readByte(data[6]);
	long byte8 = readByte(data[7]);

	return (unsigned long) (byte1 << 56) + (byte2 << 48) + (byte3 << 40) + (byte4 << 32) 
		+ (byte5 << 24) + (byte6 << 16) + (byte7 << 8) + byte8;
}