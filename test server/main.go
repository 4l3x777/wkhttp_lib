package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
)

// Config
const (
	ListenIP   = "0.0.0.0"
	ListenPort = 4443
	HTTPPort   = 8080
	HTTPSPort  = 8443
)

func main() {
	// 1. Generate common self-signed cert
	cert, err := generateCertificate()
	if err != nil {
		log.Fatal("Certificate generation failed:", err)
	}

	var wg sync.WaitGroup
	wg.Add(4)

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

	// 4. Start HTTP Server for Chunked Tests (plain)
	go func() {
		defer wg.Done()
		startHTTPServer(ListenIP, HTTPPort)
	}()

	// 5. Start HTTPS Server for Chunked Tests (TLS)
	go func() {
		defer wg.Done()
		startHTTPSServer(ListenIP, HTTPSPort, cert)
	}()

	log.Printf("  Multi-Protocol Server Started:\n")
	log.Printf("   ├─ TLS/DTLS: %s:%d (TCP & UDP)\n", ListenIP, ListenPort)
	log.Printf("   ├─ HTTP:     http://%s:%d\n", ListenIP, HTTPPort)
	log.Printf("   └─ HTTPS:    https://%s:%d\n", ListenIP, HTTPSPort)
	log.Println("\n  Test endpoints:")
	log.Println("   POST http://localhost:8080/upload     (chunked multipart)")
	log.Println("   POST https://localhost:8443/upload    (chunked multipart)")
	log.Println("   POST http://localhost:8080/echo       (echo test)")

	wg.Wait()
}

// --- HTTP Server (Plain) ---
func startHTTPServer(ip string, port int) {
	mux := http.NewServeMux()
	setupHTTPRoutes(mux)

	addr := fmt.Sprintf("%s:%d", ip, port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	log.Printf("[HTTP] Listening on %s...\n", addr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("[HTTP] Error: %v\n", err)
	}
}

// --- HTTPS Server (TLS) ---
func startHTTPSServer(ip string, port int, cert tls.Certificate) {
	mux := http.NewServeMux()
	setupHTTPRoutes(mux)

	addr := fmt.Sprintf("%s:%d", ip, port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
		},
	}

	log.Printf("[HTTPS] Listening on %s...\n", addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Printf("[HTTPS] Error: %v\n", err)
	}
}

// --- HTTP Routes Setup ---
func setupHTTPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/upload", handleChunkedUpload)
	mux.HandleFunc("/echo", handleEcho)
	mux.HandleFunc("/", handleRoot)
}

// --- Handler: Root ---
func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "  Go Test Server Ready\n")
	fmt.Fprintf(w, "Endpoints:\n")
	fmt.Fprintf(w, "  POST /upload - Chunked multipart upload\n")
	fmt.Fprintf(w, "  POST /echo   - Echo test\n")
}

// --- Handler: Echo ---
func handleEcho(w http.ResponseWriter, r *http.Request) {
	log.Printf("[HTTP] %s %s from %s\n", r.Method, r.URL.Path, r.RemoteAddr)
	log.Printf("[HTTP] Transfer-Encoding: %s\n", r.Header.Get("Transfer-Encoding"))

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	log.Printf("[HTTP] Received %d bytes\n", len(body))

	// Echo response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","received":%d,"body":"%s"}`, len(body), string(body[:min(100, len(body))]))
}

// --- Handler: Chunked Upload ---
func handleChunkedUpload(w http.ResponseWriter, r *http.Request) {
	log.Printf("[UPLOAD] %s %s from %s\n", r.Method, r.URL.Path, r.RemoteAddr)
	log.Printf("[UPLOAD] Content-Type: %s\n", r.Header.Get("Content-Type"))
	log.Printf("[UPLOAD] Transfer-Encoding: %s\n", r.Header.Get("Transfer-Encoding"))
	log.Printf("[UPLOAD] Content-Length: %s\n", r.Header.Get("Content-Length"))

	// Check if chunked
	isChunked := r.Header.Get("Transfer-Encoding") == "chunked"
	log.Printf("[UPLOAD] Is Chunked: %v\n", isChunked)

	// Read body in chunks
	totalBytes := int64(0)
	buffer := make([]byte, 8192)
	chunkCount := 0

	startTime := time.Now()

	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)
			chunkCount++

			// Log progress every 1MB
			if totalBytes%(1024*1024) == 0 || chunkCount%100 == 0 {
				log.Printf("[UPLOAD] Progress: %d MB (%d chunks)\n", totalBytes/(1024*1024), chunkCount)
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("[UPLOAD] Read error: %v\n", err)
			http.Error(w, "Upload failed", http.StatusBadRequest)
			return
		}
	}

	duration := time.Since(startTime)
	speed := float64(totalBytes) / duration.Seconds() / 1024 / 1024 // MB/s

	log.Printf("[UPLOAD]   Complete: %d bytes (%d chunks) in %.2fs (%.2f MB/s)\n",
		totalBytes, chunkCount, duration.Seconds(), speed)

	// Success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
		"status": "success",
		"received_bytes": %d,
		"chunks": %d,
		"duration_ms": %.0f,
		"speed_mbps": %.2f,
		"chunked": %v
	}`, totalBytes, chunkCount, duration.Seconds()*1000, speed, isChunked)
}

// --- TLS (TCP) Server ---
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

	log.Printf("[TLS] Listening TCP/%d...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[TLS] Accept error:", err)
			continue
		}
		go handleConnection(conn, "TLS")
	}
}

// --- DTLS (UDP) Server ---
func startDTLSServer(ip string, port int, cert tls.Certificate) {
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

	log.Printf("[DTLS] Listening UDP/%d...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("[DTLS] Accept error:", err)
			continue
		}
		go handleConnection(conn, "DTLS")
	}
}

// --- Connection Handler (TLS/DTLS) ---
func handleConnection(conn net.Conn, proto string) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[%s] New connection from %s\n", proto, remoteAddr)

	buf := make([]byte, 4096)

	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("[%s] Connection closed (%s): %v\n", proto, remoteAddr, err)
			return
		}

		msg := string(buf[:n])
		log.Printf("[%s] RECV (%s): %s\n", proto, remoteAddr, msg)

		// Delay for DTLS
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
			Organization: []string{"Universal TLS/DTLS/HTTP Test Server"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("0.0.0.0"),
			net.ParseIP("1.1.1.1"),
		},
		DNSNames: []string{"localhost"},
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

// Helper
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
