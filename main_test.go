package shadowsocks2

import (
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	// Setup server
	cancelServer, err := Run(Flags{Server: "ss://AEAD_CHACHA20_POLY1305:123456@127.0.0.1:8848"})
	if err != nil {
		t.Fatal(err)
	}
	// Setup client
	cancelClient, err := Run(Flags{Client: "ss://AEAD_CHACHA20_POLY1305:123456@127.0.0.1:8848", Socks: "127.0.0.1:1280"})
	if err != nil {
		t.Fatal(err)
	}
	// Cancel both
	cancelChan := make(chan struct{})
	go func() {
		cancelClient()
		cancelServer()
		cancelChan <- struct{}{}
	}()
	select {
	case <-cancelChan:
	case <-time.After(time.Second * 10):
		t.Fatal("Fail to cancel in 10 seconds")
	}
}
