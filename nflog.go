/*
Package nflog is a pure Go client library for capturing and parsing NFLog messages
*/
package nflog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"syscall"
)

type NFLog struct {
	fd  int
	seq uint32

	c      chan Msg
	errors chan error

	conf *Config
}

func New(conf *Config) (*NFLog, error) {
	var err error

	err = conf.Validate()
	if err != nil {
		return nil, err
	}

	n := &NFLog{c: make(chan Msg), conf: conf}
	if conf.Return.Errors {
		n.errors = make(chan error)
	}

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

	for _, g := range conf.Groups {
		// Bind to groups
		err = n.sendNFConfigCmd(NFULNL_CFG_CMD_BIND, syscall.AF_INET, g)
		if err != nil {
			syscall.Close(n.fd)
			return nil, err
		}

		// Set CopyMeta only
		err = n.sendNFConfigMode(g, conf.CopyRange)
		if err != nil {
			syscall.Close(n.fd)
			return nil, err
		}
	}

	go n.readNFMsg()

	return n, nil
}

func (n NFLog) Messages() <-chan Msg {
	return n.c
}

func (n NFLog) Errors() <-chan error {
	return n.errors
}

func (n *NFLog) sendNFConfigCmd(cmd uint8, family uint8, resId uint16) error {
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

func (n *NFLog) sendNFConfigMode(resId uint16, copyLen uint16) error {
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
		if err != nil {
			if n.conf.Return.Errors {
				n.errors <- ReaderError(err.Error())
			}
			if err == syscall.ENOBUFS {
				// Non critical error, continue
				continue
			}
			return
		}

		err = n.parseNFMsg(buffer[:s])
		if err != nil {
			if n.conf.Return.Errors {
				n.errors <- ParserError(err.Error())
			}
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
			return errors.New("message was truncated")
		}

		// Check only packets
		if header.Type == ((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET) {
			err := n.parseNFPacket(buffer[16 : msgLen])
			if err != nil {
				return errors.New("failed to parse NFPacket: " + err.Error())
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

	var m Msg
	m.Family = header.Family
	m.Group = htons(header.ResId)

	var tlvHeader nflogTlv
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
		case NFULA_IFINDEX_INDEV:
			var i uint32
			binary.Read(reader, binary.BigEndian, &i)
			m.InDev = &i
		case NFULA_IFINDEX_OUTDEV:
			var o uint32
			binary.Read(reader, binary.BigEndian, &o)
			m.OutDev = &o
		case NFULA_HWADDR:
			var addr HwAddr
			binary.Read(reader, binary.BigEndian, &addr)
			m.HwAddr = &addr
		case NFULA_HWTYPE:
			var t uint16
			binary.Read(reader, binary.BigEndian, &t)
			m.MacLayerType = &t
			reader.Seek(2, io.SeekCurrent) // Padding
		case NFULA_HWHEADER:
			payload := make([]byte, align4_16(payloadLen))
			reader.Read(payload)
			m.MacLayer = payload[:payloadLen]
		case NFULA_MARK:
			var mark uint32
			binary.Read(reader, binary.BigEndian, &mark)
			m.Mark = &mark
		case NFULA_TIMESTAMP:
			var sec int64
			var usec int64
			binary.Read(reader, binary.BigEndian, &sec)
			binary.Read(reader, binary.BigEndian, &usec)
			m.Sec = &sec
			m.Usec = &usec
		default:
			reader.Seek(int64(align4_16(payloadLen)), io.SeekCurrent)
		}
	}

	// Send Msg to socket
	n.c <- m

	return nil
}
