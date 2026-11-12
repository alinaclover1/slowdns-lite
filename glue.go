package dnstt

import (
	"fmt"
	"net"
	"strings"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

// QType: 16 = TXT, 10 = NULL. Dipakai oleh kode klien dnstt yang sudah dipatch.
var QType uint16 = 16

// Data record NULL adalah byte mentah; TXT dibungkus potongan <=255 byte.
func decodeRData(p []byte) ([]byte, error) {
	if QType == 10 {
		return p, nil
	}
	return dns.DecodeRDataTXT(p)
}

// Run menjalankan klien dnstt (UDP resolver) dan mendengarkan TCP di listen.
// Fungsi ini blocking sampai terowongan gagal.
func Run(pubkeyHex, domainName, resolver, listen string) error {
	pubkey, err := noise.DecodeKey(strings.TrimSpace(pubkeyHex))
	if err != nil {
		return fmt.Errorf("kunci publik tidak valid: %v", err)
	}
	domain, err := dns.ParseName(strings.TrimSpace(domainName))
	if err != nil {
		return fmt.Errorf("NS tidak valid: %v", err)
	}
	localAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		return err
	}
	r := strings.TrimSpace(resolver)
	r = strings.TrimPrefix(r, "udp://")
	if _, _, err := net.SplitHostPort(r); err != nil {
		r = net.JoinHostPort(r, "53")
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", r)
	if err != nil {
		return fmt.Errorf("resolver tidak valid: %v", err)
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	pconn := NewDNSPacketConn(udp, remoteAddr, domain)
	return run(pubkey, domain, localAddr, remoteAddr, pconn)
}
