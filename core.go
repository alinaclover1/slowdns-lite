// Inti SlowDNS Lite: dnstt (terowongan DNS) -> SSH -> tun2socks (lwIP, mendukung ARM 32-bit).
package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	t2s "github.com/eycorsican/go-tun2socks/core"
	"golang.org/x/crypto/ssh"

	"golib/dnstt"
)

var (
	mu      sync.Mutex
	cur     atomic.Pointer[ssh.Client]
	alive   atomic.Bool
	dnsAddr string
	dnsSem  = make(chan struct{}, 8)
)

func freePort() (int, error) {
