package nflog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"syscall"
)

type NFLog struct {
	fd  int
	seq uint32

	c chan NFLogMsg
}

func New(c *Config) (*NFLog, error) {
	var err error

	err = c.Validate()
	if err != nil {
		return nil, err
	}

	n := &NFLog{c: make(chan NFLogMsg)}

	n.fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}

	// Send Unbind
	err = n.sendNFConfigCmd(NFULNL_CFG_CMD_PF_UNBIND, syscall.AF_INET, 0)
	if err != nil {
		syscall.Close(n.fd)
		return nil, err
	}

	// Send Bind
	err = n.sendNFConfigCmd(NFULNL_CFG_CMD_PF_BIND, syscall.AF_INET, 0)
	if err != nil {
		syscall.Close(n.fd)
		return nil, err
	}

	for _, g := range c.Groups {
		// Bind to groups
		err = n.sendNFConfigCmd(NFULNL_CFG_CMD_BIND, syscall.AF_INET, htons(g))
		if err != nil {
			syscall.Close(n.fd)
			return nil, err
		}

		// Set CopyMeta only
		err = n.sendNFConfigMode(htons(g), 0x40000000)
		if err != nil {
			syscall.Close(n.fd)
			return nil, err
		}
	}

	go n.readNFMsg()

	return n, nil
}

func (n NFLog) Messages() <-chan NFLogMsg {
	return n.c
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

func (n *NFLog) sendNFConfigMode(resId uint16, copyLen uint32) error {
	c := newNFConfigMode(resId, copyLen)
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

func (n *NFLog) readNFMsg() {
	defer syscall.Close(n.fd)

	buffer := make([]byte, 65536)
	for {
		s, _, err := syscall.Recvfrom(n.fd, buffer, 0)
		if err == syscall.ENOBUFS {
			continue
		}
		if err != nil {
			return
		}

		err = n.parseNFMsg(buffer[:s])
		if err != nil {
			fmt.Printf("Failed to parse NFMsg: %s", err.Error())
		}
	}
}

func (n *NFLog) parseNFMsg(buffer []byte) error {
	for len(buffer) > 0 {
		reader := bytes.NewReader(buffer)

		// Read header
		var header nlmsghdr
		binary.Read(reader, binary.LittleEndian, &header)

		msgLen := header.Len

		if msgLen > uint32(len(buffer)) {
			return fmt.Errorf("message was truncated")
		}

		// Check only packets
		if header.Type == ((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET) {
			err := n.parseNFPacket(buffer[16 : msgLen-1])
			if err != nil {
				return fmt.Errorf("failed to parse NFPacket: %s", err.Error())
			}
		}

		buffer = buffer[msgLen:]
	}

	return nil
}

func (n *NFLog) parseNFPacket(buffer []byte) error {
	reader := bytes.NewReader(buffer)

	// Read Header
	var header nflogHeader
	binary.Read(reader, binary.LittleEndian, &header)

	// TODO Check Family && ResId (nlog group)
	var tlvHeader nflogTlv

	var m NFLogMsg

	for reader.Len() != 0 {
		err := binary.Read(reader, binary.LittleEndian, &tlvHeader)
		if err != nil {
			return err
		}

		payloadLen := tlvHeader.Len - 4

		switch tlvHeader.Type {
		case NFULA_PREFIX:
			payload := make([]byte, align4_16(payloadLen))
			reader.Read(payload)
			m.Prefix = string(payload[:payloadLen-1]) // Removes NUL Byte
		case NFULA_PAYLOAD:
			payload := make([]byte, align4_16(payloadLen))
			reader.Read(payload)
			m.Payload = payload[:payloadLen]
		case NFULA_UID:
			var uid uint32
			binary.Read(reader, binary.BigEndian, &uid)
			m.UID = &uid
		case NFULA_GID:
			var gid uint32
			binary.Read(reader, binary.BigEndian, &gid)
			m.GID = &gid
		default:
			reader.Seek(int64(align4_16(payloadLen)), io.SeekCurrent)
		}
	}

	// Send Msg to socket
	n.c <- m

	return nil
}
