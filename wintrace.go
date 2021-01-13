package wintrace

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const INADDR_NONE = 0xffffffff

const IP_SUCCESS uint32 = 0
const IP_BUF_TOO_SMALL uint32 = 11001
const IP_DEST_NET_UNREACHABLE uint32 = 11002
const IP_DEST_HOST_UNREACHABLE uint32 = 11003
const IP_DEST_PROT_UNREACHABLE uint32 = 11004
const IP_DEST_PORT_UNREACHABLE uint32 = 11005
const IP_NO_RESOURCES uint32 = 11006
const IP_BAD_OPTION uint32 = 11007
const IP_HW_ERROR uint32 = 11008
const IP_PACKET_TOO_BIG uint32 = 11009
const IP_REQ_TIMED_OUT uint32 = 11010
const IP_BAD_REQ uint32 = 11011
const IP_BAD_ROUTE uint32 = 11012
const IP_TTL_EXPIRED_TRANSIT uint32 = 11013
const IP_TTL_EXPIRED_REASSEM uint32 = 11014
const IP_PARAM_PROBLEM uint32 = 11015
const IP_SOURCE_QUENCH uint32 = 11016
const IP_OPTION_TOO_BIG uint32 = 11017
const IP_BAD_DESTINATION uint32 = 11018
const IP_GENERAL_FAILURE uint32 = 11050

var (
	Ws2_32              = syscall.NewLazyDLL("Ws2_32.dll")
	Iphlpapi            = syscall.NewLazyDLL("Iphlpapi.dll")
	inet_addr_proc      = Ws2_32.NewProc("inet_addr")
	IcmpCreateFile_proc = Iphlpapi.NewProc("IcmpCreateFile")
	IcmpSendEcho_proc   = Iphlpapi.NewProc("IcmpSendEcho")
)

type IP_OPTION_INFORMATION struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type ICMP_ECHO_REPLY struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	USHORT        uint16
	Data          uintptr
	Options       IP_OPTION_INFORMATION
}

func backtoIP4(ipInt32 uint32) string {
	ipInt := int64(ipInt32)
	b0 := strconv.FormatInt(ipInt&0xff, 10)
	b1 := strconv.FormatInt((ipInt>>8)&0xff, 10)
	b2 := strconv.FormatInt((ipInt>>16)&0xff, 10)
	b3 := strconv.FormatInt((ipInt>>24)&0xff, 10)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

type TranceResponse struct {
	IP  string `json:"ip"`
	TTL int    `json:"ttl"`
}

func Trace(ipStr string) ([]TranceResponse, error) {
	u, err := url.Parse(ipStr)
	if err != nil {
		return nil, err
	}
	var res = make([]TranceResponse, 0)
	var SendData [32]byte
	copy(SendData[:], []byte("Data Buffer"))
	host := u.Hostname()
	if strings.EqualFold("localhost", host) {
		host = "127.0.0.1"
	}

	var ip, _ = syscall.BytePtrFromString(host)
	var reply ICMP_ECHO_REPLY
	var ReplySize = unsafe.Sizeof(reply) + unsafe.Sizeof(SendData)
	var ReplyBuffer = make([]byte, int(ReplySize))
	var maxTTL = 256
	ip_addr, _, err := inet_addr_proc.Call(uintptr(unsafe.Pointer(ip)))
	if ip_addr == INADDR_NONE {
		return nil, errors.New("Address resolution error")
	}
	fd, _, err := IcmpCreateFile_proc.Call()

	if syscall.Handle(fd) == syscall.InvalidHandle {
		return nil, errors.New(fmt.Sprintf("Failed to create handle:% s", err.Error()))
	}
	//TODO:: fix sping forever while waiting on a response
	for i := 0; i <= maxTTL; i++ {
		requestOptions := IP_OPTION_INFORMATION{
			Ttl: uint8(i),
		}
		_, _, err = IcmpSendEcho_proc.Call(fd, ip_addr, uintptr(unsafe.Pointer(&SendData[0])),
			unsafe.Sizeof(SendData), uintptr(unsafe.Pointer(&requestOptions)), uintptr(unsafe.Pointer(&ReplyBuffer[0])),
			ReplySize, 1000)

		reply := (*ICMP_ECHO_REPLY)(unsafe.Pointer(&ReplyBuffer[0]))

		replyItem := TranceResponse{
			IP:  backtoIP4(reply.Address),
			TTL: i,
		}
		res = append(res, replyItem)
		if strings.EqualFold(host, replyItem.IP) {
			break
		}
	}

	return res, nil
}
