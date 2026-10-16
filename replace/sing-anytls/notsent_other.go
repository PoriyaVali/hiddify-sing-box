//go:build !linux && !darwin

package anytls

import "net"

func limitUnsent(net.Conn) {}
