#pragma once

int readByte(unsigned char data)
{
	return (int)data & 0xFF;
}
short readShort(unsigned char* data)
{
	int byte1 = readByte(data[1]);
	int byte2 = readByte(data[0]);
	return (short) (byte2 << 8) + byte1;
}

int readInt(unsigned char* data)
{
	int byte1 = readByte(data[3]);
	int byte2 = readByte(data[2]);
	int byte3 = readByte(data[1]);
	int byte4 = readByte(data[0]);
	return (byte4 << 24) + (byte3 << 16) + (byte2 << 8) + byte1;
}

long readLong(unsigned char* data)
{
	long byte1 = readByte(data[7]);
	long byte2 = readByte(data[6]);
	long byte3 = readByte(data[5]);
	long byte4 = readByte(data[4]);
	long byte5 = readByte(data[3]);
	long byte6 = readByte(data[2]);
	long byte7 = readByte(data[1]);
	long byte8 = readByte(data[0]);

	return (byte8 << 56) + (byte7 << 48) + (byte6 << 40) + (byte5 << 32) + (byte4 << 24) + (byte3 << 16) + (byte2 << 8) + byte1;
}