package shadowsocks2

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
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
