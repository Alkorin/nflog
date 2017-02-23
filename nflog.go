package nflog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"syscall"
)

type NFLog struct {
	callback func([]byte)
	fd       int
	seq      uint32
}

func New(f func([]byte)) (*NFLog, error) {
	var err error

	n := &NFLog{callback: f}

	n.fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(n.fd)

	// Send Unbind
	err = n.sendNFConfigCmd(NFULNL_CFG_CMD_PF_UNBIND, syscall.AF_INET, 0)
	if err != nil {
		return nil, err
	}

	// Send Bind
	err = n.sendNFConfigCmd(NFULNL_CFG_CMD_PF_BIND, syscall.AF_INET, 0)
	if err != nil {
		return nil, err
	}

	// Bind Grp 32
	err = n.sendNFConfigCmd(NFULNL_CFG_CMD_BIND, syscall.AF_INET, 0x2000)
	if err != nil {
		return nil, err
	}

	// Set CopyMeta only
	err = n.sendNFConfigMode(0x2000)
	if err != nil {
		return nil, err
	}

	for {
		buffer := make([]byte, 65536)
		s, _, err := syscall.Recvfrom(n.fd, buffer, 0)
		if err != nil {
			fmt.Printf("%+v\n", err)
			return nil, err
		}

		n.parseNFMsg(buffer[:s])
	}

	return n, nil
}

func (n *NFLog) sendNFConfigCmd(cmd NFULNL_CFG_CMD, family uint8, resId uint16) error {
	c := newNFConfigCmd(cmd, family, resId)
	c.Header.Seq = n.seq

	n.seq++

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, c)

	err := syscall.Sendto(n.fd, buf.Bytes(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	if err != nil {
		return err
	}

	// Wait reply
	// TODO Parse/Check it
	reply := make([]byte, 2048)
	_, _, err = syscall.Recvfrom(n.fd, reply, 0)

	return err
}

func (n *NFLog) sendNFConfigMode(resId uint16) error {
	c := newNFConfigMode(resId)
	c.Header.Seq = n.seq

	n.seq++

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, c)

	err := syscall.Sendto(n.fd, buf.Bytes(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	if err != nil {
		return err
	}

	// Wait reply
	// TODO Parse/Check it
	reply := make([]byte, 2048)
	_, _, err = syscall.Recvfrom(n.fd, reply, 0)

	return err
}

func (n *NFLog) parseNFMsg(buffer []byte) error {

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
			packet := buffer[16 : msgLen-1]
			fmt.Printf("Payload:%+v\n", packet)
			n.parseNFPacket(packet)
		}

		buffer = buffer[msgLen:]
	}

	return nil
}

func (n *NFLog) parseNFPacket(buffer []byte) {
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
			n.callback(payload[:tlvHeader.Len-4])
		default:
			reader.Seek(int64(align4_16(tlvHeader.Len-4)), io.SeekCurrent)
		}

	}
}
