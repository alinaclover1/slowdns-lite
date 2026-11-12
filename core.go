// Inti SlowDNS Lite: dnstt (terowongan DNS) -> SSH -> SOCKS5 lokal -> tun2socks.
package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
	"golang.org/x/crypto/ssh"

	"golib/dnstt"
)

var (
	mu      sync.Mutex
	cur     atomic.Pointer[ssh.Client]
	alive   atomic.Bool
	socksLn net.Listener
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

// Connect membuka terowongan DNS, login SSH, lalu menyalakan SOCKS5 lokal.
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
	local := "127.0.0.1:" + strconv.Itoa(port)

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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cli.Close()
		return err
	}
	socksLn = ln
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
	go serve(ln)
	return nil
}

// StartTun menyalakan tun2socks pada fd TUN dari VpnService.
func StartTun(fd int) error {
	mu.Lock()
	defer mu.Unlock()
	if socksLn == nil {
		return errors.New("belum tersambung")
	}
	port := socksLn.Addr().(*net.TCPAddr).Port
	engine.Insert(&engine.Key{
		Proxy:    "socks5://127.0.0.1:" + strconv.Itoa(port),
		Device:   "fd://" + strconv.Itoa(fd),
		LogLevel: "warn",
	})
	engine.Start()
	return nil
}

// Alive: false kalau sesi SSH sudah putus.
func Alive() bool { return cur.Load() != nil && alive.Load() }

// ---------- SOCKS5 minimal: CONNECT + UDP (khusus DNS port 53) ----------

func serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

func handle(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 300)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	cmd, atyp := buf[1], buf[3]
	var host string
	switch atyp {
	case 1:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(append([]byte(nil), buf[:4]...)).String()
	case 4:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(append([]byte(nil), buf[:16]...)).String()
	case 3:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		n := int(buf[0])
		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			return
		}
		host = string(buf[:n])
	default:
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(buf[:2]))

	switch cmd {
	case 1:
		cli := cur.Load()
		if cli == nil {
			c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		r, err := cli.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer r.Close()
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		done := make(chan struct{}, 2)
		go func() { io.Copy(r, c); closeWrite(r); done <- struct{}{} }()
		go func() { io.Copy(c, r); closeWrite(c); done <- struct{}{} }()
		<-done
		select {
		case <-done:
		case <-time.After(60 * time.Second):
		}
	case 3:
		udpAssoc(c)
	default:
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func udpAssoc(c net.Conn) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer pc.Close()
	rep := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(rep[8:], uint16(pc.LocalAddr().(*net.UDPAddr).Port))
	c.Write(rep)
	go func() { io.Copy(io.Discard, c); pc.Close() }()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		go udpPacket(pc, from, append([]byte(nil), buf[:n]...))
	}
}

// Hanya DNS (port 53) yang diteruskan, lewat DNS-over-TCP di dalam SSH.
func udpPacket(pc net.PacketConn, from net.Addr, p []byte) {
	if len(p) < 10 || p[2] != 0 {
		return
	}
	var off int
	switch p[3] {
	case 1:
		off = 8
	case 4:
		off = 20
	case 3:
		off = 5 + int(p[4])
	default:
		return
	}
	hl := off + 2
	if len(p) < hl || binary.BigEndian.Uint16(p[off:hl]) != 53 {
		return
	}
	resp, err := dnsTCP(p[hl:])
	if err != nil {
		return
	}
	out := append(append([]byte(nil), p[:hl]...), resp...)
	pc.WriteTo(out, from)
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
