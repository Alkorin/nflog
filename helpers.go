package nflog

func align4_32(v uint32) uint32 {
	return (v + 3) & 0xFFFFFFFC
}

func align4_16(v uint16) uint16 {
	return (v + 3) & 0xFFFC
}
