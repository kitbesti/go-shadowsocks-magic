package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ihciah/go-shadowsocks-magic/core"
	"github.com/ihciah/go-shadowsocks-magic/magic"
	"github.com/ihciah/go-shadowsocks-magic/socks"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
}

var logger = log.New(os.Stderr, "", log.Lshortfile|log.LstdFlags)

func logf(f string, v ...interface{}) {
	if config.Verbose {
		logger.Output(2, fmt.Sprintf(f, v...))
	}
}

func main() {

	var flags struct {
		Client    string
		Server    string
		Cipher    string
		Key       string
		Password  string
		Keygen    int
		Socks     string
		RedirTCP  string
		RedirTCP6 string
		TCPTun    string
		UDPTun    string
		UDPSocks  bool
		HTTPHost  string // 新增：HTTP伪装Host
		DNSDomain string // 新增：DNS伪装域名
	}

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "AEAD_CHACHA20_POLY1305", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
	flag.IntVar(&flags.Keygen, "keygen", 0, "generate a base64url-encoded random key of given length in byte")
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.StringVar(&flags.Client, "c", "", "client connect address or url")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.BoolVar(&flags.UDPSocks, "u", false, "(client-only) Enable UDP support for SOCKS")
	flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
	flag.StringVar(&flags.TCPTun, "tcptun", "", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.HTTPHost, "http-host", "www.example.com", "HTTP伪装Host") // 新增
	flag.StringVar(&flags.DNSDomain, "dns-domain", "example.com", "DNS伪装域名")      // 新增
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.Parse()

	if flags.Keygen > 0 {
		key := make([]byte, flags.Keygen)
		io.ReadFull(rand.Reader, key)
		fmt.Println(base64.URLEncoding.EncodeToString(key))
		return
	}

	if flags.Client == "" && flags.Server == "" {
		flag.Usage()
		return
	}

	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}

	if flags.Client != "" { // client mode
		addr := flags.Client
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		if flags.UDPTun != "" {
			for _, tun := range strings.Split(flags.UDPTun, ",") {
				p := strings.Split(tun, "=")
				go udpLocalWithMask(p[0], addr, p[1], ciph.PacketConn, flags.DNSDomain)
			}
		}

		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTunMagicWithMask(p[0], addr, p[1], ciph.StreamConn, flags.HTTPHost)
			}
		}

		if flags.Socks != "" {
			socks.UDPEnabled = flags.UDPSocks
			go socksLocalMagicWithMask(flags.Socks, addr, ciph.StreamConn, flags.HTTPHost)
			if flags.UDPSocks {
				go udpSocksLocalWithMask(flags.Socks, addr, ciph.PacketConn, flags.DNSDomain)
			}
		}

		if flags.RedirTCP != "" {
			go redirLocalWithMask(flags.RedirTCP, addr, ciph.StreamConn, flags.HTTPHost)
		}

		if flags.RedirTCP6 != "" {
			go redir6LocalWithMask(flags.RedirTCP6, addr, ciph.StreamConn, flags.HTTPHost)
		}
	}

	if flags.Server != "" { // server mode
		addr := flags.Server
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			log.Fatal(err)
		}

		// Global Buffer Table
		GBT := make(magic.GlobalBufferTable)

		go udpRemoteWithMask(addr, ciph.PacketConn, flags.DNSDomain)
		go tcpRemoteMagicWithMask(addr, ciph.StreamConn, &GBT, flags.HTTPHost)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}

// 新增：带伪装参数的入口函数
func udpLocalWithMask(laddr, server, target string, shadow func(net.PacketConn) net.PacketConn, dnsDomain string) {
	udpLocalMask(laddr, server, target, shadow, dnsDomain)
}

func udpSocksLocalWithMask(laddr, server string, shadow func(net.PacketConn) net.PacketConn, dnsDomain string) {
	udpSocksLocalMask(laddr, server, shadow, dnsDomain)
}

func udpRemoteWithMask(addr string, shadow func(net.PacketConn) net.PacketConn, dnsDomain string) {
	udpRemoteMask(addr, shadow, dnsDomain)
}

func tcpTunMagicWithMask(addr, server, target string, shadow func(net.Conn) net.Conn, httpHost string) {
	tcpTunMagicMask(addr, server, target, shadow, httpHost)
}

func socksLocalMagicWithMask(addr, server string, shadow func(net.Conn) net.Conn, httpHost string) {
	socksLocalMagicMask(addr, server, shadow, httpHost)
}

func redirLocalWithMask(addr, server string, shadow func(net.Conn) net.Conn, httpHost string) {
	redirLocalMask(addr, server, shadow, httpHost)
}

func redir6LocalWithMask(addr, server string, shadow func(net.Conn) net.Conn, httpHost string) {
	redir6LocalMask(addr, server, shadow, httpHost)
}

func tcpRemoteMagicWithMask(addr string, shadow func(net.Conn) net.Conn, GBT *magic.GlobalBufferTable, httpHost string) {
	tcpRemoteMagicMask(addr, shadow, GBT, httpHost)
}

// 生成标准DNS查询头部
func buildDNSHeader(domain string) []byte {
	// 以 www.[domain] 查询A记录为例
	labels := strings.Split(domain, ".")
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w'}
	for _, l := range labels {
		dns = append(dns, byte(len(l)))
		dns = append(dns, []byte(l)...)
	}
	dns = append(dns, 0x00, 0x00, 0x01, 0x00, 0x01)
	return dns
}
