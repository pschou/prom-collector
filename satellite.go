//
//  This package was written by Paul Schou in Dec 2020
//
//
package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type DNS struct {
	Addr string
	Time time.Time
}

var target_addr = ""
var DNSCache = make(map[string]DNS, 0)
var keyFile = ""
var certFile = ""
var keypair *tls.Certificate
var keypair_count = 0
var keypair_mu sync.RWMutex
var rootFile = ""
var root_count = 0
var rootpool *x509.CertPool
var certs_loaded = make(map[string]bool, 0)
var debug = false

var secureCollector bool
var secureTarget bool
var verifyCollector bool
var verifyTarget bool
var uHost = ""
var tHost = ""
var httpProxy = ""
var method = "GET"

var openCh = make(chan int, 3)
var closeCh = make(chan int, 1)

var url_target *url.URL
var url_collector *url.URL

var backoff = false
var threads = 3

func loadKeys() {
	keypair_mu.RLock()
	defer keypair_mu.RUnlock()
	var err error

	tmp_key, err_k := tls.LoadX509KeyPair(certFile, keyFile)
	if err_k != nil {
		if keypair == nil {
			log.Fatalf("failed to loadkey pair: %s", err)
		}
		keypair_count++
		log.Println("WARNING: Cannot load keypair (cert/key)", certFile, keyFile, "attempt:", keypair_count)
		if keypair_count > 10 {
			log.Fatalf("failed to loadkey pair: %s", err)
		}
	} else {
		if debug {
			log.Println("Loaded keypair", certFile, keyFile)
		}
		keypair = &tmp_key
		keypair_count = 0
	}

	err_r := LoadCertficatesFromFile(rootFile)
	if err_r != nil {
		if rootpool == nil {
			log.Fatalf("failed to load CA: %s", err)
		}
		root_count++
		log.Println("WARNING: Cannot load CA file", rootFile, "attempt:", root_count)
		if root_count > 10 {
			log.Fatalf("failed to CA: %s", err)
		}
	} else {
		if debug {
			log.Println("Loaded CA", rootFile)
		}
		root_count = 0
	}

}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Prometheus Satellite Utility, written by Paul Schou github@paulschou.com in December 2020\nPrsonal use only, provided AS-IS -- not responsible for loss.\nUsage implies agreement.\n\n Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	var collector = flag.String("collector", "http://localhost:9550/instance/test", "Remote listen URL for connector")
	var Method = flag.String("method", method, "Method to use to connect to collector")
	var target = flag.String("target", "http://localhost/", "Local endpoint to tunnel the collector to")
	var http_proxy = flag.String("http-proxy", "", "host for establishing connections to prom-collector")
	var cert_file = flag.String("cert", "/etc/pki/server.pem", "File to load with CERT - automatically reloaded every minute")
	var key_file = flag.String("key", "/etc/pki/server.pem", "File to load with KEY - automatically reloaded every minute")
	var root_file = flag.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs - reloaded every minute by adding any new entries")
	var verify_target = flag.Bool("verify-target", true, "Verify or disable client certificate check, -verify-target=false to ignore SAN")
	var verify_collector = flag.Bool("verify-collector", true, "Verify or disable server certificate check, -verify-collector=false to ignore SAN")
	var secure_target = flag.Bool("secure-target", true, "Enforce TLS 1.2+ on client side")
	var secure_collector = flag.Bool("secure-collector", true, "Enforce TLS 1.2+ on server side")
	//var tls_host = flag.String("host", "", "Hostname to verify outgoing connection with")
	var verbose = flag.Bool("debug", false, "Verbose output")
	var in_threads = flag.Int("threads", threads, "Number of concurrent tcp streams to run to improve performance")
	flag.Parse()

	var err error
	debug = *verbose

	method = *Method
	keyFile = *key_file
	certFile = *cert_file
	rootFile = *root_file
	rootpool = x509.NewCertPool()
	verifyTarget = *verify_target
	verifyCollector = *verify_collector
	secureTarget = *secure_target
	secureCollector = *secure_collector
	threads = *in_threads
	httpProxy = *http_proxy
	if debug {
		if *http_proxy != "" {
			log.Println("using http-proxy")
		}
	}

	url_collector, err = url.Parse(*collector)
	if err != nil {
		panic(err)
	}
	{
		host, port, err := net.SplitHostPort(url_collector.Host)
		if err != nil {
			host = url_collector.Host
			port = "80"
			if url_collector.Scheme == "https" {
				port = "443"
			}
		}
		uHost = net.JoinHostPort(host, port)
	}

	url_target, err = url.Parse(*target)
	if err != nil {
		panic(err)
	}
	{
		host, port, err := net.SplitHostPort(url_target.Host)
		if err != nil {
			host = url_target.Host
			port = "80"
			if url_target.Scheme == "https" {
				port = "443"
			}
		}
		tHost = net.JoinHostPort(host, port)
	}

	if url_collector.Scheme == "https" || url_target.Scheme == "https" {
		loadKeys()
		go func() {
			ticker := time.NewTicker(time.Minute)
			for {
				select {
				case <-ticker.C:
					loadKeys()
				}
			}
		}()
	}

	if debug {
		fmt.Println("Collector url set to", *collector)
	}
	for {
		if backoff {
			if debug {
				fmt.Println("backing off")
			}
			time.Sleep(5 * time.Second)
		}
		if len(openCh) < threads {

			if debug {
				fmt.Println("open chan")
			}
			openCh <- 1
			go func() {
				mkChan()
				<-openCh
				closeCh <- 1
				if debug {
					fmt.Println("chan closed")
				}
			}()
		} else {
			<-closeCh
		}
	}
}
func mkChan() {
	var l net.Conn
	var lc net.Conn
	var err error
	if httpProxy != "" {
		if debug {
			fmt.Println("Proxy dialing ", uHost, "through", httpProxy)
		}
		if lc, err = net.Dial("tcp", httpProxy); err != nil {
			log.Println("Could not connect to proxy", err)
			backoff = true
			return
		}
		lc.Write([]byte("CONNECT " + uHost + " HTTP/1.1\n\n"))
		buf := make([]byte, 50)
		for j := 0; j < len(buf); j++ {
			_, err := lc.Read(buf[j : j+1])
			if err != nil {
				return
			}
			if buf[j] == 0xd {
				j--
			}
			if buf[j] == 0xa {
				if strings.HasPrefix(string(buf[0:j]), "HTTP/1.1 200") {
					if debug {
						log.Println("proxy returned 200")
					}
					break
				} else {
					log.Println("Proxy CONNECT command failed")
					return
				}
			}
		}
		for j := 0; j < len(buf); j++ {
			_, err := lc.Read(buf[j : j+1])
			if err != nil {
				return
			}
			if buf[j] == 0xa {
				break
			}
		}
	} else {
		if debug {
			fmt.Println("Dialing ", uHost)
		}
		if lc, err = net.Dial("tcp", uHost); err != nil {
			log.Println("Error dialing", err)
			backoff = true
			return
		}
	}
	if url_collector.Scheme == "https" {
		var config tls.Config
		if secureCollector {
			config = tls.Config{RootCAs: rootpool,
				Certificates: []tls.Certificate{},
				ClientCAs:    rootpool, InsecureSkipVerify: verifyCollector == false,
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}
		} else {
			config = tls.Config{RootCAs: rootpool,
				ClientCAs: rootpool, InsecureSkipVerify: verifyCollector == false}
		}
		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if debug {
				log.Println("  Get Cert Returning keypair")
			}
			return keypair, nil
		}

		config.Rand = rand.Reader
		if debug {
			fmt.Println("TLS Dialing ", uHost)
		}
		t := tls.Client(lc, &config)
		err = t.Handshake()
		if err != nil {
			log.Println("Error during handshake", err)
			backoff = true
			return
		}
		l = t
	} else if url_collector.Scheme == "http" {
		// we're already in the state we need the connection to be in
		l = lc
	} else {
		log.Fatal("Unknown URL scheme: " + url_collector.Scheme)
	}
	defer l.Close()

	l.Write([]byte(method + " " + url_collector.Path + " HTTP/1.1\nReflect: " + url_target.Host + " " + url_target.Path +
		"\nUser-Agent: Reflector\nHost: " + uHost + "\nContent-Length: 0\n\n"))

	//pass := make(chan bool, 1)
	pass := false
	//func() {
	buf := make([]byte, 50)
	for j := 0; j < len(buf); j++ {
		_, err := l.Read(buf[j : j+1])
		if err != nil {
			break
		}
		if buf[j] == 0xd {
			j--
		}

		if j >= 2 {
			//log.Println("read", buf[j-3:j+1])
			if string(buf[j-2:j+1]) == "GO\n" {
				pass = true
				break
			}
		}

		if j >= 4 {
			//log.Println("read", buf[j-3:j+1])
			if string(buf[j-4:j+1]) == "PING\n" {
				_, err := l.Write([]byte("PONG\n"))
				if err != nil {
					log.Println("error when replying to ping", err)
					break
				}
				if debug {
					log.Println("pingged!")
				}
				j = 0
			}
		}
	}
	if debug {
		log.Println("buf", buf, string(buf))
	}
	//pass <- false
	//}()

	//ret := <-pass
	if pass == false {
		backoff = true
		//l.Close()
	} else {
		backoff = false

		if debug {
			fmt.Println("Local target url set to", url_target)
		}

		var tc net.Conn

		if url_target.Scheme == "https" {
			var tlsConfig *tls.Config
			if secureTarget {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
					ClientCAs: rootpool, InsecureSkipVerify: verifyTarget == false,
					MinVersion:               tls.VersionTLS12,
					CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
					PreferServerCipherSuites: true,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
				}
			} else {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
					ClientCAs: rootpool, InsecureSkipVerify: verifyTarget == false}
			}

			tlsConfig.Rand = rand.Reader

			if debug {
				fmt.Println("TLS Dialing ", tHost)
			}
			if tc, err = tls.Dial("tcp", tHost, tlsConfig); err != nil {
				log.Println(err)
				backoff = true
				return
			}
		} else if url_target.Scheme == "http" {
			var err error
			if debug {
				fmt.Println("Dialing ", tHost)
			}
			if tc, err = net.Dial("tcp", tHost); err != nil {
				log.Println(err)
				backoff = true
				return
			}
		} else {
			log.Fatal("Unknown Dial URL scheme: " + url_collector.Scheme)
		}
		defer tc.Close()

		if debug {
			log.Println("connecting endpoints:", target_addr)
		}
		go io.Copy(l, tc)
		io.Copy(tc, l)
		if debug {
			log.Println("closed", target_addr)
		}
	}
}

func LoadCertficatesFromFile(path string) error {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("warning: error parsing CA cert", err)
				continue
			}
			t := fmt.Sprintf("%v%v", cert.SerialNumber, cert.Subject)
			if _, ok := certs_loaded[t]; !ok {
				if debug {
					fmt.Println(" Adding CA:", cert.Subject)
				}
				rootpool.AddCert(cert)
				certs_loaded[t] = true
			}
		}
		raw = rest
	}

	return nil
}
