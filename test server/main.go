package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
)

// Config
const (
	ListenIP   = "0.0.0.0"
	ListenPort = 4443
)

func main() {
	// 1. Generate common self-signed cert for TLS and DTLS
	cert, err := generateCertificate()
	if err != nil {
		log.Fatal("Certificate generation failed:", err)
	}

	// WaitGroup to hold main open
	var wg sync.WaitGroup
	wg.Add(2)

	// 2. Start TLS Server (TCP)
	go func() {
		defer wg.Done()
		startTLSServer(ListenIP, ListenPort, cert)
	}()

	// 3. Start DTLS Server (UDP)
	go func() {
		defer wg.Done()
		startDTLSServer(ListenIP, ListenPort, cert)
	}()

	log.Printf("TLS/DTLS Server Started on %s:%d (TCP & UDP)\n", ListenIP, ListenPort)
	wg.Wait()
}

// --- TLS (TCP) Server Implementation ---
func startTLSServer(ip string, port int, cert tls.Certificate) {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		log.Printf("[TLS] Start error: %v\n", err)
		return
	}
	defer listener.Close()

	log.Printf("[TLS] Listening TCP/%d...", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[TLS] Accept error:", err)
			continue
		}
		go handleConnection(conn, "TLS")
	}
}

// --- DTLS (UDP) Server Implementation ---
func startDTLSServer(ip string, port int, cert tls.Certificate) {
	// Configuration for Pion DTLS
	config := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ClientAuth:           dtls.NoClientCert,
	}

	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		log.Printf("[DTLS] Start error: %v\n", err)
		return
	}
	defer listener.Close()

	log.Printf("[DTLS] Listening UDP/%d...", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[DTLS] Accept error:", err)
			continue
		}
		go handleConnection(conn, "DTLS")
	}
}

// --- Common Connection Handler ---
func handleConnection(conn net.Conn, proto string) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[%s] New connection from %s\n", proto, remoteAddr)

	// Read buffer
	buf := make([]byte, 4096)

	for {
		// Timeout for read (Keep-Alive logic)
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		n, err := conn.Read(buf)
		if err != nil {
			// Check if it's a timeout vs a close
			log.Printf("[%s] Connection closed (%s): %v\n", proto, remoteAddr, err)
			return
		}

		msg := string(buf[:n])
		log.Printf("[%s] RECV (%s): %s\n", proto, remoteAddr, msg)

		// FIX: Add a small delay for DTLS to allow the client to switch to Receive mode
		if proto == "DTLS" {
			time.Sleep(200 * time.Millisecond)
		}

		// Echo response
		response := fmt.Sprintf("[%s-Server] Echo: %s", proto, msg)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("[%s] Write error: %v\n", proto, err)
			return
		}
	}
}

// --- Certificate Generator ---
func generateCertificate() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Universal TLS/DTLS Test"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0"), net.ParseIP("1.1.1.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
