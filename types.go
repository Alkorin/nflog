package nflog

import (
	"syscall"
)

type AF_FAMILY uint8

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

type NFULNL_CFG_CMD uint8
type nfulnl_msg_config_cmd struct {
	Command NFULNL_CFG_CMD
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

func newNFConfigCmd(cmd NFULNL_CFG_CMD, family uint8, resId uint16) nfConfigCmd {
	return nfConfigCmd{
		Header: nlmsghdr{
			Len:   25,
			Type:  (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			Flags: NLM_F_REQUEST | NLM_F_ACK,
			Seq:   0,
			Pid:   0,
		},
		Message: nfgenmsg{
			Family:  family,
			Version: NFNETLINK_V0,
			ResId:   resId,
		},
		Attr: nfattr{
			Len:  5,
			Type: NFULA_CFG_CMD,
		},
		Cmd: nfulnl_msg_config_cmd{
			Command: cmd,
		},
	}
}

func newNFConfigMode(resId uint16, copyLen uint32) nfConfigMode {
	return nfConfigMode{
		Header: nlmsghdr{
			Len:   30,
			Type:  (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			Flags: NLM_F_REQUEST | NLM_F_ACK,
			Seq:   0,
			Pid:   0,
		},
		Message: nfgenmsg{
			Family:  syscall.AF_UNSPEC,
			Version: NFNETLINK_V0,
			ResId:   resId,
		},
		Attr: nfattr{
			Len:  10,
			Type: NFULA_CFG_MODE,
		},
		Mode: nfulnl_msg_config_mode{
			CopyMode:  NFULNL_COPY_PACKET,
			CopyRange: copyLen,
		},
	}
}

type NFLogMsg struct {
	Payload []byte
}

type ConfigurationError string

func (err ConfigurationError) Error() string {
	return "nflog: invalid configuration (" + string(err) + ")"
}

type Config struct {
	Groups []uint16
}

func NewConfig() *Config {
	return &Config{}
}

func (c Config) Validate() error {
	if len(c.Groups) == 0 {
		return ConfigurationError("No groups defined")
	}

	if len(c.Groups) > 32 {
		return ConfigurationError("Number of groups should be <= 32")
	}

	return nil
}
