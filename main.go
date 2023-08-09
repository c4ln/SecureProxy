package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/PuerkitoBio/goquery"
)

const (
	DefaultUsername = "admin"
	DefaultPassword = "password123"
)

var blockedIPs = make(map[string]bool)
var blockedURLs = make(map[string]bool)
var debugMode bool

func initBlockedIPs() {
	// Load blocked IPs from threat intelligence feeds, honeypot lists, etc.
	// blockedIPs["1.2.3.4"] = true
	// blockedIPs["5.6.7.8"] = true
}

func updateBlockedURLs() {
	resp, err := http.Get("https://urlhaus.abuse.ch/api/v1/urls/recent/")
	if err != nil {
		log.Printf("Error fetching URLhaus data: %v\n", err)
		return
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Printf("Error parsing URLhaus data: %v\n", err)
		return
	}

	doc.Find(".table tr").Each(func(i int, row *goquery.Selection) {
		cells := row.Find("td")
		if cells.Length() >= 5 {
			url := cells.Eq(2).Text()
			blockedURLs[url] = true
		}
	})
}

func handleClient(clientConn net.Conn, serverAddr string, tlsConfig *tls.Config, proxySocks5 bool) {
	clientIP := strings.Split(clientConn.RemoteAddr().String(), ":")[0]

	if blockedIPs[clientIP] {
		log.Printf("Blocked connection from blocked IP: %s\n", clientIP)
		clientConn.Close()
		return
	}

	defer clientConn.Close()

	serverConn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Printf("Error connecting to server: %v\n", err)
		return
	}
	defer serverConn.Close()

	if proxySocks5 {
		serverConn = proxySocks5Server(serverConn, serverAddr, tlsConfig)
	}

	go io.Copy(serverConn, clientConn)
	io.Copy(clientConn, serverConn)
}

func proxySocks5Server(clientConn net.Conn, serverAddr string, tlsConfig *tls.Config) net.Conn {
	serverConn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Printf("Error connecting to server: %v\n", err)
		return nil
	}

	go io.Copy(serverConn, clientConn)
	go io.Copy(clientConn, serverConn)

	return serverConn
}

func redirectToHTTPS(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "https://"+req.Host+req.URL.String(), http.StatusPermanentRedirect)
}

func basicAuthMiddleware(next http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != username || p != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func logRequest(r *http.Request) {
	log.Printf("Request: %s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
}

func customErrorHandler(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "Custom Error Page: %d %s\n", status, http.StatusText(status))
}

func handleHTTPClient(w http.ResponseWriter, r *http.Request) {
	if debugMode {
		logRequest(r)
	}
	if _, blocked := blockedURLs[r.URL.String()]; blocked {
		http.Error(w, "Blocked: Malicious URL", http.StatusForbidden)
		return
	}

	// Connect to the upstream server
	upstreamConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", serverIP, serverPort))
	if err != nil {
		log.Printf("Error connecting to upstream server: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer upstreamConn.Close()

	// Copy data between client and upstream server
	go func() {
		_, err := io.Copy(upstreamConn, r.Body)
		if err != nil {
			log.Printf("Error copying data to upstream server: %v\n", err)
		}
		upstreamConn.Close()
	}()

	// Copy data between upstream server and client
	_, err = io.Copy(w, upstreamConn)
	if err != nil {
		log.Printf("Error copying data from upstream server: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}


func main() {
	var serverIP string
	var serverPort int
	var bindPort int
	var domain string
	var proxySocks5 bool

	initBlockedIPs()

	flag.StringVar(&serverIP, "server-ip", "", "Server IP address")
	flag.IntVar(&serverPort, "server-port", 0, "Server port")
	flag.IntVar(&bindPort, "bind-port", 0, "Bind port")
	flag.StringVar(&domain, "domain", "", "Domain name for automatic certificate generation")
	flag.BoolVar(&debugMode, "debug", false, "Enable debug mode")
	flag.BoolVar(&proxySocks5, "proxy-socks5", false, "Enable SOCKS5 proxy for .onion domains")
	flag.Parse()

	if serverIP == "" || serverPort == 0 || bindPort == 0 || domain == "" {
		fmt.Println("Usage: reverse-proxy -server-ip <ip> -server-port <port> -bind-port <port> -domain <domain> [-debug] [-proxy-socks5]")
		return
	}

	if debugMode {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}

	tlsConfig := &tls.Config{
		GetCertificate: certmagic.NewCache(certmagic.CacheOptions{
			GetCertificate: certmagic.ACMEDirector{Email: "you@example.com", AgreeTOS: true},
		}).GetCertificate,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", bindPort), tlsConfig)
	if err != nil {
		log.Printf("Error creating listener: %v\n", err)
		return
	}
	defer listener.Close()

	fmt.Printf("Listening on port %d (HTTP)...\n", bindPort)

	http.HandleFunc("/", handleHTTPClient)
	go func() {
		err := http.ListenAndServe(":80", http.HandlerFunc(redirectToHTTPS))
		if err != nil {
			log.Printf("Error starting HTTP server: %v\n", err)
		}
	}()

	// Basic Auth middleware
	http.Handle("/", basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if debugMode {
			logRequest(r)
		}
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v\n", err)
			return
		}

		go func() {
			conn := clientConn
			if domain != "" && strings.HasSuffix(domain, ".onion") && proxySocks5 {
				conn = proxySocks5Server(conn, fmt.Sprintf("%s:%d", serverIP, serverPort), tlsConfig)
			}
			handleClient(conn, fmt.Sprintf("%s:%d", serverIP, serverPort), tlsConfig, proxySocks5)
		}()
	})), DefaultUsername, DefaultPassword)

	// Graceful shutdown on SIGINT or SIGTERM
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-shutdown
		fmt.Printf("Received signal %v, shutting down...\n", sig)
		listener.Close()
	}()

	// Periodically update blocked IPs and URLs
	go func() {
		for {
			updateBlockedURLs()
			updateBlockedIPs()
			time.Sleep(1 * time.Hour) // Update IPs and URLs every hour
		}
	}()

	// Wait indefinitely
	select {}
}
