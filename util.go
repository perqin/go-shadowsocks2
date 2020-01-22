package shadowsocks2

import (
	"context"
	"io"
)

func closeOnCancel(closer io.Closer, ctx context.Context) {
	go func() {
		<-ctx.Done()
		logf("Close %v because Context %v is canceled", closer, ctx)
		closer.Close()
	}()
}
