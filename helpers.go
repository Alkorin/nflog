package nflog

func align4_32(v uint32) uint32 {
	return (v + 3) & 0xFFFFFFFC
}

func align4_16(v uint16) uint16 {
	return (v + 3) & 0xFFFC
}

func htons(v uint16) uint16 {
	return (v >> 8) | ((v & 0xFF) << 8)
}

func htonl(v uint32) uint32 {
	return ((v & 0xFF000000) >> 24) | ((v & 0x00FF0000) >> 8) | ((v & 0x0000FF00) << 8) | ((v & 0x000000FF) << 24)
}
