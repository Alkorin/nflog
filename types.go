package main

import ()

type nlmsghdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

type nfgenmsg struct {
	Family  uint8
	Version uint8
	ResId   uint16 // BigEndian
}

type nfattr struct {
	Len  uint16
	Type uint16
}

type nfulnl_msg_config_cmd struct {
	Command uint8
}

type nfulnl_msg_config_mode struct {
	CopyRange uint32 // BigEndian
	CopyMode  uint8
	_pad      uint8
}

type nfConfigCmd struct {
	Header  nlmsghdr
	Message nfgenmsg
	Attr    nfattr
	Cmd     nfulnl_msg_config_cmd
}

type nfConfigMode struct {
	Header  nlmsghdr
	Message nfgenmsg
	Attr    nfattr
	Mode    nfulnl_msg_config_mode
}

type nflogHeader struct {
	Family  uint8
	Version uint8
	ResId   uint16 // BigEndian
}

type nflogTlv struct {
	Len  uint16
	Type uint16
}
