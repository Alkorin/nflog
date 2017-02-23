package nflog

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

const (
	NFULNL_CFG_CMD_NONE NFULNL_CFG_CMD = iota
	NFULNL_CFG_CMD_BIND
	NFULNL_CFG_CMD_UNBIND
	NFULNL_CFG_CMD_PF_BIND
	NFULNL_CFG_CMD_PF_UNBIND
)

const NFULNL_COPY_NONE = 0x00
const NFULNL_COPY_META = 0x01
const NFULNL_COPY_PACKET = 0x02

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
