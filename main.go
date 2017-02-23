package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"syscall"
)

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
