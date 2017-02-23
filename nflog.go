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
}

func New(f func([]byte)) *NFLog{

  nfLog := &NFLog{callback: f}

	reply := make([]byte, 2048)

	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		panic(err)
	}

	var seq uint32

	// Send Unbind
	configCmd := newNFConfigCmd(NFULNL_CFG_CMD_PF_UNBIND, syscall.AF_INET, 0)
	configCmd.Header.Seq = seq

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
	configCmd = newNFConfigCmd(NFULNL_CFG_CMD_PF_BIND, syscall.AF_INET, 0)
	configCmd.Header.Seq = seq

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
	configCmd = newNFConfigCmd(NFULNL_CFG_CMD_BIND, syscall.AF_UNSPEC, 0x2000)
	configCmd.Header.Seq = seq

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
	configMode := newNFConfigMode(0x2000)
	configMode.Header.Seq = seq

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

		nfLog.parseNFMsg(buffer[:n])
	}

  return nfLog
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
