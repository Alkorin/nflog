package main

import (
	"syscall"
	//  "unsafe"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const AF_INET = 2
const AF_UNSPEC = 2

const NFNETLINK_V0 = 0

const NLM_F_REQUEST = 1
const NLM_F_ACK = 4

const NFNL_SUBSYS_ULOG = 4

const NFULNL_MSG_PACKET = 0
const NFULNL_MSG_CONFIG = 1
const NFULNL_MSG_MAX = 2

const NFULA_CFG_UNSPEC = 0
const NFULA_CFG_CMD = 1
const NFULA_CFG_MODE = 2
const NFULA_CFG_NLBUFSIZ = 3
const NFULA_CFG_TIMEOUT = 4
const NFULA_CFG_QTHRESH = 5
const NFULA_CFG_FLAGS = 6
const __NFULA_CFG_MAX = 7

const NFULNL_CFG_CMD_NONE = 0
const NFULNL_CFG_CMD_BIND = 1
const NFULNL_CFG_CMD_UNBIND = 2
const NFULNL_CFG_CMD_PF_BIND = 3
const NFULNL_CFG_CMD_PF_UNBIND = 4

const NFULNL_COPY_NONE = 0x00
const NFULNL_COPY_META = 0x01
const NFULNL_COPY_PACKET = 0x02

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

const NFULA_PACKET_HDR = 1         /* nflog_packet_hdr_t */
const NFULA_MARK = 2               /* packet mark from skbuff */
const NFULA_TIMESTAMP = 3          /* nflog_timestamp_t for skbuff's time stamp */
const NFULA_IFINDEX_INDEV = 4      /* ifindex of device on which packet received (possibly bridge group) */
const NFULA_IFINDEX_OUTDEV = 5     /* ifindex of device on which packet transmitted (possibly bridge group) */
const NFULA_IFINDEX_PHYSINDEV = 6  /* ifindex of physical device on which packet received (not bridge group) */
const NFULA_IFINDEX_PHYSOUTDEV = 7 /* ifindex of physical device on which packet transmitted (not bridge group) */
const NFULA_HWADDR = 8             /* nflog_hwaddr_t for hardware address */
const NFULA_PAYLOAD = 9            /* packet payload */
const NFULA_PREFIX = 10            /* text string - null-terminated, count includes NUL */
const NFULA_UID = 11               /* UID owning socket on which packet was sent/received */
const NFULA_SEQ = 12               /* sequence number of packets on this NFLOG socket */
const NFULA_SEQ_GLOBAL = 13        /* sequence number of pakets on all NFLOG sockets */
const NFULA_GID = 14               /* GID owning socket on which packet was sent/received */
const NFULA_HWTYPE = 15            /* ARPHRD_ type of skbuff's device */
const NFULA_HWHEADER = 16          /* skbuff's MAC-layer header */
const NFULA_HWLEN = 17             /* length of skbuff's MAC-layer header */

func main() {
	reply := make([]byte, 2048)

	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		panic(err)
	}

	var seq uint32

	// Send Unbind
	configCmd := nfConfigCmd{
		Header: nlmsghdr{
			Len:   25,
			Type:  (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			Flags: NLM_F_REQUEST | NLM_F_ACK,
			Seq:   seq,
			Pid:   0,
		},
		Message: nfgenmsg{
			Family:  AF_INET,
			Version: NFNETLINK_V0,
			ResId:   0,
		},
		Attr: nfattr{
			Len:  5,
			Type: NFULA_CFG_CMD,
		},
		Cmd: nfulnl_msg_config_cmd{
			Command: NFULNL_CFG_CMD_PF_UNBIND,
		},
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, configCmd)
	fmt.Printf("=> %+v\n", buf.Bytes())

	err = syscall.Sendto(s, buf.Bytes(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Err: [%+v]\n", err)

	{
		n, sa, err := syscall.Recvfrom(s, reply, 0)
		fmt.Printf("n:%+v sa:%+v, err: %+v, data:%+v\n", n, sa, err, reply[:n])
	}

	seq++

	// Send Bind
	configCmd = nfConfigCmd{
		Header: nlmsghdr{
			Len:   25,
			Type:  (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			Flags: NLM_F_REQUEST | NLM_F_ACK,
			Seq:   seq,
			Pid:   0,
		},
		Message: nfgenmsg{
			Family:  AF_INET,
			Version: NFNETLINK_V0,
			ResId:   0,
		},
		Attr: nfattr{
			Len:  5,
			Type: NFULA_CFG_CMD,
		},
		Cmd: nfulnl_msg_config_cmd{
			Command: NFULNL_CFG_CMD_PF_BIND,
		},
	}

	buf = new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, configCmd)
	fmt.Printf("=> %+v\n", buf.Bytes())

	err = syscall.Sendto(s, buf.Bytes(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Err: [%+v]\n", err)

	{
		n, sa, err := syscall.Recvfrom(s, reply, 0)
		fmt.Printf("n:%+v sa:%+v, err: %+v, data:%+v\n", n, sa, err, reply[:n])
	}

	seq++

	// Bind Grp 32
	configCmd = nfConfigCmd{
		Header: nlmsghdr{
			Len:   25,
			Type:  (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			Flags: NLM_F_REQUEST | NLM_F_ACK,
			Seq:   seq,
			Pid:   0,
		},
		Message: nfgenmsg{
			Family:  AF_UNSPEC,
			Version: NFNETLINK_V0,
			ResId:   0x2000,
		},
		Attr: nfattr{
			Len:  5,
			Type: NFULA_CFG_CMD,
		},
		Cmd: nfulnl_msg_config_cmd{
			Command: NFULNL_CFG_CMD_BIND,
		},
	}

	buf = new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, configCmd)
	fmt.Printf("=> %+v\n", buf.Bytes())

	err = syscall.Sendto(s, buf.Bytes(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Err: [%+v]\n", err)

	{
		n, sa, err := syscall.Recvfrom(s, reply, 0)
		fmt.Printf("n:%+v sa:%+v, err: %+v, data:%+v\n", n, sa, err, reply[:n])
	}

	seq++

	// Set CopyMeta only
	configMode := nfConfigMode{
		Header: nlmsghdr{
			Len:   30,
			Type:  (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			Flags: NLM_F_REQUEST | NLM_F_ACK,
			Seq:   seq,
			Pid:   0,
		},
		Message: nfgenmsg{
			Family:  AF_UNSPEC,
			Version: NFNETLINK_V0,
			ResId:   0x0,
		},
		Attr: nfattr{
			Len:  10,
			Type: NFULA_CFG_CMD,
		},
		Mode: nfulnl_msg_config_mode{
			CopyMode:  NFULNL_COPY_META,
			CopyRange: 0,
		},
	}

	buf = new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, configMode)
	fmt.Printf("=> %+v\n", buf.Bytes())

	err = syscall.Sendto(s, buf.Bytes(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Err: [%+v]\n", err)

	{
		n, sa, err := syscall.Recvfrom(s, reply, 0)
		fmt.Printf("n:%+v sa:%+v, err: %+v, data:%+v\n", n, sa, err, reply[:n])
	}

	for {
		buffer := make([]byte, 65536)
		n, sa, err := syscall.Recvfrom(s, buffer, 0)
		if err != nil {
			panic(err)
		}

		fmt.Printf("n:%+v sa:%+v, err: %+v, data:%+v\n", n, sa, err, buffer[:n])

		parse(buffer[:n])
	}
}

func parse(buffer []byte) error {

	for len(buffer) > 0 {
		reader := bytes.NewReader(buffer)

		// Read header
		var header nlmsghdr
		binary.Read(reader, binary.LittleEndian, &header)

		fmt.Printf("Header: %+v\n", header)

		msgLen := header.Len

		if msgLen > uint32(len(buffer)) {
			fmt.Printf("Msg truncated, skip")
			return fmt.Errorf("TRUNC")
		}

		// Check only packets
		if header.Type == ((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET) {
			payload := buffer[16 : msgLen-1]
			fmt.Printf("Payload:%+v\n", payload)
			parseNFPacket(payload)
		}

		buffer = buffer[msgLen:]
	}
	return nil
}

func parseNFPacket(buffer []byte) {
	reader := bytes.NewReader(buffer)
	var header nflogHeader
	binary.Read(reader, binary.LittleEndian, &header)
	fmt.Printf("Packet Header: %+v\n", header)

	// TODO Check Family && ResId (nlog group)
	var tlvHeader nflogTlv

	for reader.Len() != 0 {
		err := binary.Read(reader, binary.LittleEndian, &tlvHeader)
		if err != nil {
			panic(err)
		}
		fmt.Printf("TLV Header: %+v\n", tlvHeader)

		switch tlvHeader.Type {
		case NFULA_PAYLOAD:
			payload := make([]byte, align4_16(tlvHeader.Len-4))
			reader.Read(payload)
			parsePacket(payload[:tlvHeader.Len-4])
		default:
			reader.Seek(int64(align4_16(tlvHeader.Len-4)), io.SeekCurrent)
		}

	}
}

func parsePacket(payload []byte) {
	fmt.Printf("DATA: %+v\n", payload)
}

func align4_32(v uint32) uint32 {
	return (v + 3) & 0xFFFFFFFC
}

func align4_16(v uint16) uint16 {
	return (v + 3) & 0xFFFC
}
