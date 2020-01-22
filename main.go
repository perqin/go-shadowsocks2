package shadowsocks2

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"sync"
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

func Run(flags Flags) (context.CancelFunc, error) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			return nil, err
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
				return nil, err
			}
		}

		udpAddr := addr

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			return nil, err
		}

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, false)
			if err != nil {
				return nil, err
			}
		}

		if flags.UDPTun != "" {
			for _, tun := range strings.Split(flags.UDPTun, ",") {
				p := strings.Split(tun, "=")
				wg.Add(1)
				go func() {
					udpLocal(ctx, p[0], udpAddr, p[1], ciph.PacketConn)
					wg.Done()
				}()
			}
		}

		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				wg.Add(1)
				go func() {
					tcpTun(ctx, p[0], addr, p[1], ciph.StreamConn)
					wg.Done()
				}()
			}
		}

		if flags.Socks != "" {
			socks.UDPEnabled = flags.UDPSocks
			wg.Add(1)
			go func() {
				socksLocal(ctx, flags.Socks, addr, ciph.StreamConn)
				wg.Done()
			}()
			if flags.UDPSocks {
				wg.Add(1)
				go func() {
					udpSocksLocal(ctx, flags.Socks, udpAddr, ciph.PacketConn)
					wg.Done()
				}()
			}
		}

		if flags.RedirTCP != "" {
			wg.Add(1)
			go func() {
				redirLocal(ctx, flags.RedirTCP, addr, ciph.StreamConn)
				wg.Done()
			}()
		}

		if flags.RedirTCP6 != "" {
			wg.Add(1)
			go func() {
				redir6Local(ctx, flags.RedirTCP6, addr, ciph.StreamConn)
				wg.Done()
			}()
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
				return nil, err
			}
		}

		udpAddr := addr

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, true)
			if err != nil {
				return nil, err
			}
		}

		ciph, err := core.PickCipher(cipher, key, password)
		if err != nil {
			return nil, err
		}

		wg.Add(1)
		go func() {
			udpRemote(ctx, udpAddr, ciph.PacketConn)
			wg.Done()
		}()
		wg.Add(1)
		go func() {
			tcpRemote(ctx, addr, ciph.StreamConn)
			wg.Done()
		}()
	}

	return func() {
		cancelFunc()
		wg.Wait()
	}, nil
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
