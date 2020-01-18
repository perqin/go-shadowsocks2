package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type Config struct {
	Verbose    bool
	UDPTimeout time.Duration
}

var config Config

func SetConfig(cfg Config) {
	config = cfg
}

type Flags struct {
	Client     string
	Server     string
	Cipher     string
	Key        string
	Password   string
	Keygen     int
	Socks      string
	RedirTCP   string
	RedirTCP6  string
	TCPTun     string
	UDPTun     string
	UDPSocks   bool
	Plugin     string
	PluginOpts string
}

func main() {

	var flags Flags

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
	flag.StringVar(&flags.Plugin, "plugin", "", "Enable SIP003 plugin. (e.g., v2ray-plugin)")
	flag.StringVar(&flags.PluginOpts, "plugin-opts", "", "Set SIP003 plugin options. (e.g., \"server;tls;host=mydomain.me\")")
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

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	if err := Run(flags, ctx); err != nil {
		log.Fatal(err)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	killPlugin()
	cancel()
}

func Run(flags Flags, ctx context.Context) error {

	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			return err
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
				return err
			}
		}

		udpAddr := addr

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			return err
		}

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, false)
			if err != nil {
				return err
			}
		}

		if flags.UDPTun != "" {
			for _, tun := range strings.Split(flags.UDPTun, ",") {
				p := strings.Split(tun, "=")
				go udpLocal(ctx, p[0], udpAddr, p[1], ciph.PacketConn)
			}
		}

		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTun(ctx, p[0], addr, p[1], ciph.StreamConn)
			}
		}

		if flags.Socks != "" {
			socks.UDPEnabled = flags.UDPSocks
			go socksLocal(ctx, flags.Socks, addr, ciph.StreamConn)
			if flags.UDPSocks {
				go udpSocksLocal(ctx, flags.Socks, udpAddr, ciph.PacketConn)
			}
		}

		if flags.RedirTCP != "" {
			go redirLocal(ctx, flags.RedirTCP, addr, ciph.StreamConn)
		}

		if flags.RedirTCP6 != "" {
			go redir6Local(ctx, flags.RedirTCP6, addr, ciph.StreamConn)
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
				return err
			}
		}

		udpAddr := addr

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, true)
			if err != nil {
				return err
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			return err
		}

		go udpRemote(ctx, udpAddr, ciph.PacketConn)
		go tcpRemote(ctx, addr, ciph.StreamConn)
	}

	return nil
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
