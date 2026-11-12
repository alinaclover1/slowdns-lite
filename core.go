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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func dialSSH(addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// Connect membuka terowongan DNS lalu login SSH.
// qtype: "TXT" atau "NULL". dnsServer: DNS yang dipakai HP (lewat SSH).
func Connect(resolver, ns, pubkey, qtype, user, pass, dnsServer string) error {
	mu.Lock()
	defer mu.Unlock()
	if cur.Load() != nil {
		return errors.New("sudah berjalan")
	}
	if strings.EqualFold(qtype, "NULL") {
		dnstt.QType = 10
	} else {
		dnstt.QType = 16
	}
	if _, _, err := net.SplitHostPort(dnsServer); err != nil {
		dnsServer = net.JoinHostPort(dnsServer, "53")
	}
	dnsAddr = dnsServer

	port, err := freePort()
	if err != nil {
		return err
	}
	local := fmt.Sprintf("127.0.0.1:%d", port)

	tunErr := make(chan error, 1)
	go func() { tunErr <- dnstt.Run(pubkey, ns, resolver, local) }()

	// Host key tidak diperiksa: jalurnya sudah diautentikasi oleh kunci publik Noise dnstt.
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				a := make([]string, len(qs))
				for i := range a {
					a[i] = pass
				}
				return a, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         45 * time.Second,
	}

	var cli *ssh.Client
	var lastErr error
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-tunErr:
			return fmt.Errorf("terowongan DNS berhenti: %v", e)
		default:
		}
		cli, lastErr = dialSSH(local, cfg)
		if lastErr == nil {
			break
		}
		if strings.Contains(lastErr.Error(), "unable to authenticate") {
			return fmt.Errorf("login SSH ditolak (cek user/sandi): %v", lastErr)
		}
		time.Sleep(time.Second)
	}
	if cli == nil {
		return fmt.Errorf("gagal tersambung lewat DNS (cek resolver, NS, kunci, tipe): %v", lastErr)
	}

	cur.Store(cli)
	alive.Store(true)

	go func() { cli.Wait(); alive.Store(false) }()
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for range t.C {
			if !alive.Load() {
				return
			}
			done := make(chan struct{})
			go func() {
				cli.SendRequest("keepalive@openssh.com", true, nil)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(60 * time.Second):
				cli.Close()
				return
			}
		}
	}()
	return nil
}

// StartTun menyambungkan fd TUN dari VpnService ke SSH lewat tumpukan lwIP.
func StartTun(fd int) error {
	mu.Lock()
	defer mu.Unlock()
	if cur.Load() == nil {
		return errors.New("belum tersambung")
	}
	f := os.NewFile(uintptr(fd), "tun")
	stack := t2s.NewLWIPStack()
	t2s.RegisterTCPConnHandler(tcpH{})
	t2s.RegisterUDPConnHandler(udpH{})
	t2s.RegisterOutputFn(func(data []byte) (int, error) { return f.Write(data) })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := f.Read(buf)
			if err != nil {
				alive.Store(false)
				return
			}
			stack.Write(buf[:n])
		}
	}()
	return nil
}

// Alive: false kalau sesi SSH atau TUN sudah putus.
func Alive() bool { return cur.Load() != nil && alive.Load() }

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// ---------- TCP: setiap koneksi dari HP dibuka lewat SSH ----------

type tcpH struct{}

func (tcpH) Handle(conn net.Conn, target *net.TCPAddr) error {
	cli := cur.Load()
	if cli == nil {
		return errors.New("tidak tersambung")
	}
	go relay(conn, cli, target.String())
	return nil
}

func relay(c net.Conn, cli *ssh.Client, addr string) {
	defer c.Close()
	r, err := cli.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer r.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(r, c); closeWrite(r); done <- struct{}{} }()
	go func() { io.Copy(c, r); closeWrite(c); done <- struct{}{} }()
	<-done
	select {
	case <-done:
	case <-time.After(60 * time.Second):
	}
}

// ---------- UDP: hanya DNS (port 53), lewat DNS-over-TCP di dalam SSH ----------

type udpH struct{}

func (udpH) Connect(conn t2s.UDPConn, target *net.UDPAddr) error {
	if target.Port != 53 {
		return errors.New("UDP selain DNS tidak didukung")
	}
	return nil
}

func (udpH) ReceiveTo(conn t2s.UDPConn, data []byte, addr *net.UDPAddr) error {
	q := append([]byte(nil), data...)
	go func() {
		defer conn.Close()
		resp, err := dnsTCP(q)
		if err != nil {
			return
		}
		conn.WriteFrom(resp, addr)
	}()
	return nil
}

func dnsTCP(q []byte) ([]byte, error) {
	cli := cur.Load()
	if cli == nil {
		return nil, errors.New("tidak tersambung")
	}
	dnsSem <- struct{}{}
	defer func() { <-dnsSem }()
	conn, err := cli.Dial("tcp", dnsAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	t := time.AfterFunc(10*time.Second, func() { conn.Close() })
	defer t.Stop()
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	r := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, r); err != nil {
		return nil, err
	}
	return r, nil
}
