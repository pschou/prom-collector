//
//  This package was written by Paul Schou in Dec 2020
//
//  Prometheus Collector - basic end point package for sending prometheus metrics!
//
package main

import (
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"math/rand"
	//"encoding/json"
	"bufio"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	//"io"
	"github.com/pschou/go-params"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	//"regexp"
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Prom struct {
	Path        string
	OrigPath    string
	Hash        [16]byte
	Size        int
	Time        time.Time
	TimeStr     string
	LabelSlice  []string
	LabelMap    map[string]string
	UseEndpoint bool
	endPoints   chan *reflector
	LastSeen    string
}
type reflector struct {
	conn      net.Conn
	close     chan int
	urlSuffix string
	urlHost   string
}

var Proms = map[[16]byte]Prom{}
var PromsLock sync.Mutex

var compressed = false

var version = "0.1"
var urlPrefix = ""
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
var basePath = "/dev/shm/collector"
var jsonPath = "/dev/shm/metrics.json"
var excludePath *regexp.Regexp
var excludeMetric *regexp.Regexp

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
	params.Usage = func() {
		fmt.Fprintf(params.CommandLine.Output(), "Prometheus Collector, written by Paul Schou (github.com/pschou/prom-collector) in December 2020\nProvided AS-IS, not responsible for loss, see LICENSE.  Usage implies agreement. (Version: %s)\n\nUsage: %s [options...]\n\n", version, os.Args[0])
		params.PrintDefaults()
	}
	var listen = params.String("listen", ":9550", "Listen address for metrics", "HOST:PORT")
	var prefix = params.String("prefix", "/collector", "Used for all incoming requests, useful for a reverse proxy endpoint\n", "URL_PREFIX")
	var verify_server = params.Bool("verify-server", true, "Verify or disable server certificate check", "BOOL")
	var secure_server = params.Bool("secure-server", true, "Enforce TLS 1.2+ on server side", "BOOL")
	var tls_enabled = params.Bool("tls", false, "Enable listener TLS", "BOOL")
	params.PresVar(&debug, "debug", "Verbose output")
	params.StringVar(&basePath, "path", basePath, "Path into which to put the prometheus data", "DIRECTORY")
	params.StringVar(&jsonPath, "json", jsonPath, "Path into which to put all the prometheus endpoints for polling\n", "JSON_FILE")
	exclude_path := params.String("exclude-path", "", "Path filter for removing metric push endpoints", "REGEX")
	exclude_metric := params.String("exclude-metric", "", "Metric filter for removing metric from dump", "REGEX")
	//var jsonstatic_path = params.String("json-static", jsonPath, "Path into which to put just static prometheus json endpoints for polling")
	//var jsonstatic_path = params.String("dynamic-list", jsonPath, "Path into which to put just static prometheus json endpoints for polling")
	//params.SetUsageIndent(23)
	params.PresVar(&compressed, "compress", "Turn on gzip compression")

	params.GroupingSet("Certificate")
	params.StringVar(&certFile, "cert", "/etc/pki/server.pem", "File to load with CERT - automatically reloaded every minute\n", "FILE")
	params.StringVar(&keyFile, "key", "/etc/pki/server.pem", "File to load with KEY - automatically reloaded every minute\n", "FILE")
	params.StringVar(&rootFile, "ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs - reloaded every minute by adding any new entries\n", "FILE")

	params.CommandLine.Indent = 2

	params.Parse()

	if *exclude_path != "" {
		excludePath, _ = regexp.Compile(*exclude_path)
	}
	if *exclude_metric != "" {
		excludeMetric, _ = regexp.Compile(*exclude_metric)
	}

	urlPrefix = strings.TrimRight(*prefix, "/")
	if urlPrefix != "" && urlPrefix[0] != '/' {
		urlPrefix = "/" + urlPrefix
	}

	rootpool = x509.NewCertPool()

	_, err := os.Stat(basePath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.Mkdir(basePath, 0755)
			if err != nil {
				log.Fatal("Directory does not exist, nor could it be made " + basePath)
			}
		} else {
			log.Fatal("Directory is not accessible " + basePath)
		}
	}

	var l net.Listener
	if *tls_enabled {
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

		var config tls.Config
		if *secure_server {
			config = tls.Config{RootCAs: rootpool,
				Certificates: []tls.Certificate{},
				ClientCAs:    rootpool, InsecureSkipVerify: *verify_server == false,
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
				ClientCAs: rootpool, InsecureSkipVerify: *verify_server == false}
		}
		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if debug {
				log.Println("  Get Cert Returning keypair")
			}
			return keypair, nil
		}

		//config.Rand = rand.Reader
		if debug {
			fmt.Println("TLS Listening on", *listen)
		}
		if l, err = tls.Listen("tcp", *listen, &config); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		if debug {
			fmt.Println("Listening on", *listen)
		}
		if l, err = net.Listen("tcp", *listen); err != nil {
			log.Fatal(err)
		}
	}

	go func() {
		for now := range time.Tick(10 * time.Second) {
			createJson()
			if debug {
				log.Println(now, "pinging all reflectors")
			}
			PromsArr := make([]Prom, 0)
			PromsLock.Lock()
			for _, prom := range Proms {
				PromsArr = append(PromsArr, prom)
			}
			PromsLock.Unlock()
			for _, prom := range PromsArr {
				if prom.UseEndpoint {
					count := len(prom.endPoints)
					for ic := 0; ic < count; ic++ {
						pass := make(chan bool, 1)

						if debug {
							log.Println("test started...len of endpoints:", len(prom.endPoints))
						}

						//for i := 0; i < len(prom.endPoints); i++ {
						//var test_ref *reflector
						test_ref := <-prom.endPoints
						if test_ref.conn == nil {
							continue
						}
						if debug {
							log.Println("  ping:", prom.Path)
						}
						go func() {
							buf := make([]byte, 50)
							_, err := test_ref.conn.Write([]byte("PING\n"))
							if err == nil {
								for j := 0; j < len(buf); j++ {
									_, err := test_ref.conn.Read(buf[j : j+1])
									if err != nil {
										break
									}
									if buf[j] == 0xd {
										j--
									}

									if j >= 4 {
										//log.Println("read", buf[j-3:j+1])
										if string(buf[j-4:j+1]) == "PONG\n" {
											//log.Println("got reply!")
											prom.endPoints <- test_ref
											prom.Time = time.Now()
											prom.LastSeen = test_ref.conn.RemoteAddr().String()
											pass <- true
											return
										}
									}
								}
							}
							test_ref.conn.Close()
							//test_ref.conn = nil
						}()
						select {
						case <-pass:
							if debug {
								log.Println("  YES pong:", prom.Path)
							}
						case <-time.After(3 * time.Second):
							// the read from ch has timed out
							if debug {
								log.Println("  NO pong:", prom.Path)
							}

							if test_ref.conn != nil {
								test_ref.conn.Close()
								//test_ref.conn = nil
							}
						}

						if debug {
							log.Println("finished... len of endpoints:", len(prom.endPoints))
						}
					}
				}
			}
		}
	}()

	defer l.Close()
	for {
		conn, err := l.Accept() // Wait for a connection.

		if err != nil {
			fmt.Println("Error on accept", err)
			continue
		}
		if debug {
			fmt.Println("New connection from", conn.RemoteAddr())
		}

		go func(conn net.Conn) {
			defer conn.Close()
			c := bufio.NewReader(conn)
			buf_size := 257 * 1024
			buf := make([]byte, buf_size) // simple buffer for incoming requests
			path := ""
			method := ""
			urlSuffix := ""
			urlHost := ""
			cont100 := false
			contLen := -1
			failure := ""
			ch := "\nContent-Type: text/html; charset=UTF-8"
			srv := "\nServer: Prom Collector - Written by Paul Schou (github.com/pschou/prom-collector)\n\n"
			headers := []string{}

			// read input until emtpy line (http header ending)
			for i := 0; i < buf_size-1; i++ { // Read one charater at a time
				if _, err := c.Read(buf[i : i+1]); err != nil {
					break
				}
				if buf[i] == 0xa { // New line to parse...
					s := string(buf[0 : i+1])
					//if debug {
					//	log.Println("header: ", s)
					//}
					if strings.HasPrefix(s, "Expect: 100") {
						cont100 = true
					} else if strings.HasPrefix(s, "Content-Length: ") {
						parts := strings.SplitN(s, " ", 3)
						if len(parts) > 1 {
							i, err := strconv.Atoi(strings.TrimSpace(parts[1]))
							if err == nil {
								contLen = i
							} else {
								failure = "Invalid Content-Length value: " + parts[1]
							}
						} else {
							failure = "Content-Length missing length value"
						}
						headers = append(headers, s)
					} else if strings.HasPrefix(s, "POST ") || strings.HasPrefix(s, "GET ") {
						if debug {
							log.Println("request: " + s)
						}
						parts := strings.SplitN(s, " ", 4)
						method = parts[0]
						if len(parts) < 2 { //|| len(parts[1]) < 8 {
							failure = "Malformed request: " + s
							break
						}
						path = parts[1]
					} else if strings.HasPrefix(s, "Reflect: ") {
						parts := strings.SplitN(s, " ", 4)
						if len(parts) >= 3 {
							urlHost = strings.TrimSpace(parts[1])
							urlSuffix = strings.TrimSpace(parts[2])
						} else {
							failure = "Malformed reflect: " + s
							break
						}
					} else if strings.HasPrefix(s, "Connection: ") {
						headers = append(headers, "Connection: close\n")
					} else if i <= 1 { // end of connect request!
						break
					} else {
						headers = append(headers, s)
					}

					i = -1 // reset the buffer scanner to 0
				}
			}

			// we need a path
			if path == "" {
				failure = "Missing path, with target label value pairs"
			}

			// print out any errors
			if urlPrefix != "" {
				if urlHost == "" && strings.HasPrefix(path, urlPrefix+"/") == false {
					conn.Write([]byte("HTTP/1.1 302 Moved\nLocation: " + urlPrefix + "/" + srv))
					return
				}
				path = strings.TrimPrefix(path, urlPrefix)
			}
			path = strings.TrimSpace(path)

			// make sure any POST request comes with the content-length for reading
			if method == "POST" && urlHost == "" {
				if contLen < 0 && failure == "" {
					failure = "Missing Content-Length header"
				} else if contLen < 3 && failure == "" {
					failure = "Content-Length too short for data"
				}
			}
			if failure != "" {
				conn.Write([]byte("HTTP/1.1 404 Error: " + failure + cl(failure) + srv + failure))
				return
			}

			//			if failure != "" {
			//				if debug {
			//					log.Println("  failure: " + failure)
			//				}
			//				conn.Write([]byte("HTTP/1.1 500 Error: " + failure + cl(failure) + srv + failure))
			//				return
			//			}

			// Return the last written JSON for external queries
			if method == "GET" && path == "/json" {
				f, err := os.Open(jsonPath)
				if err == nil {
					io.Copy(conn, f)
				}
				return
			}

			// get the index and list endpoints
			if method == "GET" && (path == "" || path == "/") {
				var buffer bytes.Buffer
				buffer.WriteString("<h3>List of endpoints seen:</h3>\n")
				PromsArr := make([]Prom, 0)
				PromsLock.Lock()
				for _, prom := range Proms {
					PromsArr = append(PromsArr, prom)
				}
				PromsLock.Unlock()
				// sort our list of Proms by path
				sort.SliceStable(PromsArr, func(i, j int) bool {
					return PromsArr[i].Path < PromsArr[j].Path
				})
				for _, p := range PromsArr {
					if p.UseEndpoint {
						buffer.WriteString(fmt.Sprintf("<a href=\"-%s/\">%v: %v</a> - @%s %v<br>\n", p.Path[1:], p.Path[4:], p.LabelSlice, p.LastSeen, p.Time))
					} else {
						buffer.WriteString(fmt.Sprintf("<a href=\"-%s\">%v: %v</a> - %v<br>\n", p.Path[1:], p.Path[4:], p.LabelSlice, p.Time))
					}
				}
				s := "Prom-Collector" + buffer.String()
				conn.Write([]byte("HTTP/1.1 200 Okay" + cl(s) + ch + srv + s))
				//c.Close()
				return
			}

			// break out the path and build up the hash
			prom := &Prom{Time: time.Now(), LabelSlice: []string{}, LabelMap: make(map[string]string), UseEndpoint: false, OrigPath: path}
			prom.TimeStr = fmt.Sprintf("%v", prom.Time.UnixNano()/1e6)
			parts := strings.Split(strings.Trim(path[1:], "/ \r\t"), "/")
			hash_url := false // assume not hash address then test if it is
			if len(parts) > 1 && len(parts[0]) == 3 && len(parts[1]) == 32 && parts[0][0] == '-' {
				hash_url = true
			}

			// Build the hash value for the URL value provided
			if !hash_url {
				if excludePath != nil && excludePath.MatchString(path) {
					log.Println("Excluded metrics from:", conn.RemoteAddr(), ",for path:", path)
					// drop due to exclude filter
					//c.Close()
					return
				}

				if len(parts)%2 != 0 && failure == "" {
					failure = "Path \"/" + strings.Trim(path[1:], "/ \r\t") +
						"\" must have even pairs, be in format " + urlPrefix + "/LABEL_1/VALUE_1/LABEL_2/VALUE_2 / ..."
				} else {
					for i := 0; i < len(parts); i = i + 2 {
						if check_label_name(parts[i]) == false || parts[i] == "" {
							failure = "Label \"" + parts[i] + "\" in path must have valid prometheus label name"
							break
						}
						lbl := strings.TrimSpace(parts[i])
						val, err := url.QueryUnescape(strings.TrimSpace(parts[i+1]))
						if err != nil {
							failure = "Unable to parse label value in url \"" + parts[i+1] + "\""
							break
						}
						prom.LabelMap[lbl] = val
						prom.LabelSlice = append(prom.LabelSlice, fmt.Sprintf("%s=%s", lbl, fmt.Sprintf("%q", val)))
					}
				}
				if failure != "" {
					conn.Write([]byte("HTTP/1.1 500 Error: " + failure + cl(failure) + srv + failure))
					return
				}
				sort.Strings(prom.LabelSlice)
				prom.Hash = md5.Sum([]byte(strings.Join(prom.LabelSlice, "\n")))
				prom.Path = fmt.Sprintf("/%02x/%x", prom.Hash[0], prom.Hash)
			}

			// Handle the incoming reflection satellite connection
			if urlHost != "" {
				ref := &reflector{conn: conn, urlSuffix: urlSuffix, urlHost: urlHost, close: make(chan int, 1)}
				PromsLock.Lock()
				if p, ok := Proms[prom.Hash]; ok && p.UseEndpoint == false {
					delete(Proms, prom.Hash)
				}
				if _, ok := Proms[prom.Hash]; !ok {
					prom.endPoints = make(chan *reflector, 10)
					prom.UseEndpoint = true
					prom.LastSeen = conn.RemoteAddr().String()
					Proms[prom.Hash] = *prom
				} else {
					p := Proms[prom.Hash]
					p.Time = time.Now()
				}
				//createJson()
				//fmt.Println("New connection from", conn.RemoteAddr())
				//Proms[prom.Hash].Time = time.Now()
				Proms[prom.Hash].endPoints <- ref
				PromsLock.Unlock()
				if debug {
					log.Println("--waiting to close sub connection")
				}
				<-ref.close
				if debug {
					log.Println("--Closing sub connection")
				}
				//c.Close()
				return
			}

			if failure != "" {
				conn.Write([]byte("HTTP/1.1 500 Error: " + failure + cl(failure) + srv + failure))
				return
			}

			// handle the get method for returning results to the prometheus client
			if method == "GET" {
				PromsArr := make([]Prom, 0)
				PromsLock.Lock()
				for _, p := range Proms {
					PromsArr = append(PromsArr, p)
				}
				PromsLock.Unlock()
				for _, p := range PromsArr {

					if debug {
						log.Println("comparing value for path redirect", path, "->", p.OrigPath)
						//	log.Println("comparing value for path redirect", []byte(path), "->", []byte(p.OrigPath))
					}
					if p.OrigPath == strings.TrimRight(path, "/") {
						//if debug {
						//	log.Println("using map value for path redirect", path, "->", p.Path)
						//}
						if p.UseEndpoint {
							conn.Write([]byte("HTTP/1.1 302 Redirect to add slash\nLocation: " + urlPrefix + p.Path + "/" + srv))
							return
						}
						/*path = p.Path
						if p.UseEndpoint {
							path = path + "/"
						}*/
					}
				}
				//if len(parts) > 2 && len(parts[1]) == 3 && len(parts[2]) == 32 {
				//if len(parts) > 2 && len(parts[1]) == 3 && len(parts[2]) == 32 {
				if hash_url {
					parts := strings.SplitN(path, "/", 4)
					hash_buf := make([]byte, 16)
					hex.Decode(hash_buf, []byte(parts[2]))
					hash := [16]byte{}
					copy(hash[:], hash_buf)
					if len(parts) > 3 {
						var PromHashed Prom
						for {
							var ok bool
							PromsLock.Lock()
							PromHashed, ok = Proms[hash]
							PromsLock.Unlock()
							if ok {
								break
							}
							if debug {
								log.Println("Waiting for endpoint to become available")
							}
							time.Sleep(2 * time.Second)
							if conn.RemoteAddr() == nil {
								return
							}
						}
						if PromHashed.UseEndpoint {
							if debug {
								log.Println("Using channel connection for request")
							}

							if len(parts) < 4 {
								conn.Write([]byte("HTTP/1.1 302 Redirect to add slash\nLocation: " + urlPrefix + path + "/" + srv))
								return
							}

							var ref *reflector

							for ref == nil || ref.conn == nil || ref.conn.RemoteAddr() == nil {
								if debug {
									log.Println("  read off reflector")
								}
								select {
								case ref = <-PromHashed.endPoints:
								case <-time.After(10 * time.Second):
									return
								}
							}

							if debug {
								log.Println("using reflector", ref)
							}
							for i, h := range headers {
								if strings.HasPrefix(h, "Host: ") {
									headers[i] = fmt.Sprintf("Host: %s\n", ref.urlHost)
								}
							}
							//headers = append(headers, "Host: "+ref.urlHost)
							if debug {
								fmt.Printf("GET " + ref.urlSuffix + parts[3] + " HTTP/1.1\n" + strings.Join(headers, "") + "\n\n")
							}
							ref.conn.Write([]byte("GO\nGET " + ref.urlSuffix + parts[3] + " HTTP/1.1\n" + strings.Join(headers, "") + "\n\n"))
							go io.Copy(conn, ref.conn)
							io.Copy(ref.conn, c)
							if debug {
								log.Println("Closing connections")
							}
							ref.close <- 1
							//c.Close()
							return
						}
					} else {
						// If the requested hash exists, print it out
						PromsLock.Lock()
						PromHashed := Proms[hash].Path
						PromsLock.Unlock()
						f, err := os.Open(basePath + PromHashed)
						if err == nil {
							defer f.Close()
							fi, err := f.Stat()
							if err != nil || fi.IsDir() {
								quotes := []string{"They are here someplace, have you seen the metrics?",
									"Where, oh, where did I leave those metrics now?",
									"Hmm... I think I left them, here... nope!",
									"Call the metrics detective, they're lost.",
									"Unsure!",
								}
								fmt.Fprintf(conn, "HTTP/1.1 503  %s\nContent-Type: text/text; charset=UTF-8%s# EOF\n",
									quotes[rand.Intn(len(quotes))], srv)
								failure = "Could not find " + path
							} else {
								//conn.Write([]byte("HTTP/1 200 As requested" + ct + srv))
								if compressed {
									conn.Write([]byte(fmt.Sprintf("HTTP/1.1 200 As requested\nContent-Type: text/text; charset=UTF-8%s", srv)))
									gzipReader, err := gzip.NewReader(f)
									if err != nil {
										log.Println("err reading in gzip file", err)
									}
									_, err = io.Copy(conn, gzipReader)
									if err != nil {
										log.Println("err reading in file", err)
									}
								} else {
									conn.Write([]byte(fmt.Sprintf("HTTP/1.1 200 As requested\nContent-Length: %d\nContent-Type: text/text; charset=UTF-8%s", fi.Size(), srv)))
									_, err = io.Copy(conn, f)
									if err != nil {
										log.Println("err reading in file", err)
									}
								}
								//c.flush()
								return
							}
						} else {
							failure = "Error opening metric for reading"
						} //else {
						//	failure = "Metric missing " + path
						//}
					}
				} else {
					failure = "Metric missing " + path
				}
			}

			// handle the post method
			if method == "POST" {
				prom.Size = contLen
				if cont100 {
					conn.Write([]byte("HTTP/1.1 100 Continue\n\n"))
				}

				// postpone checking for new metric until the data is saved
				os.Mkdir(fmt.Sprintf("%s/%02x", basePath, prom.Hash[0]), 0755)
				dataPath := basePath + prom.Path
				dataTmp := fmt.Sprintf("%s.%04d", dataPath, rand.Intn(9999))
				if debug {
					log.Println("creating tmp data file", dataTmp)
				}
				f, err := os.Create(dataTmp)
				if err != nil {
					log.Println("could not create tmp data file", dataTmp)
					return
				}
				defer os.Remove(dataTmp)

				var w io.Writer
				var gzipWriter *gzip.Writer
				var bufWriter *bufio.Writer

				if compressed {
					gzipWriter, _ = gzip.NewWriterLevel(f, gzip.BestSpeed)
					w = gzipWriter
				} else {
					bufWriter = bufio.NewWriter(f)
					w = bufWriter
				}

				// Create buffer reader to prevent system calls
				br := bufio.NewReader(c)

				// Log when and where the data file came from
				fmt.Fprintf(w, "# From %v on %v\n", conn.RemoteAddr(), time.Now())
				fmt.Fprintf(w, "prom_collector_timestamp %v %v\n", prom.TimeStr, prom.TimeStr)

				// Avoid duplicate HELPs or TYPEs
				HELPS := []string{}
				TYPES := []string{}

				var CountFiltered, CountMetric, CountInvalid int
				var LatestTime int64

				// This is the main parsing routine.  It has been written to try to
				// recover any prom format errors and be efficient.

				i := contLen
			PromParse:
				for j := 0; i > 0; j++ {
					n, read_err := br.Read(buf[j : j+1])
					i = i - n
					if buf[j] == 0xa || i == 0 { //|| (j > 3 && read_err != nil) || i == 0 {
						line := strings.TrimSpace(string(buf[0 : j+1]))

						if line == "" || strings.HasPrefix(line, "----------------") ||
							strings.HasPrefix(line, "Content-Disposition: ") || strings.HasPrefix(line, "Content-Type: ") {
							j = -1
							continue
						}

						// Parse the HELP line
						if strings.HasPrefix(line, "# HELP ") {
							if len(line) > 7 {
								// Loop over helps and make sure this is not a duplicate
								p := strings.SplitN(line[7:], " ", 2)
								for _, h := range HELPS {
									if p[0] == h {
										j = -1
										continue PromParse
									}
								}
								HELPS = append(HELPS, p[0])
							} else {
								// Drop any empty helps
								j = -1
								continue
							}
						}

						// Parse the TYPE line
						if strings.HasPrefix(line, "# TYPE ") {
							if len(line) > 7 {
								// Loop over helps and make sure this is not a duplicate
								p := strings.SplitN(line[7:], " ", 2)
								for _, h := range TYPES {
									if p[0] == h {
										j = -1
										continue PromParse
									}
								}
								TYPES = append(TYPES, p[0])
							} else {
								// Drop any empty types
								j = -1
								continue
							}
						}

						if strings.HasPrefix(line, "#EOF") || strings.HasPrefix(line, "# EOF") {
							// Strip off EOF as we'll add our own
							j = -1
							continue
						}

						// Pass through all other comments
						if strings.HasPrefix(line, "#") {
							fmt.Fprintf(w, "%s\n", line)
							j = -1
							continue
						}
						MetricName, MetricLabels, MetricValue, MetricTime, MetricErr := prom_getparts(line, prom.LabelMap)

						if MetricErr != "" {
							CountInvalid++
							fmt.Fprintf(w, "# %s\n", MetricErr)
						}

						if MetricTime == "" {
							MetricTime = prom.TimeStr
						} else {
							tm, err := strconv.ParseInt(MetricTime, 10, 64)
							if tm > LatestTime && err == nil {
								LatestTime = tm
							}
						}

						if excludeMetric != nil && excludeMetric.MatchString(MetricName) {
							// drop due to exclude filter
							CountFiltered++
						} else {
							CountMetric++

							if MetricName != "" {
								if MetricLabels == "" {
									fmt.Fprintf(w, "%s %s %s\n", MetricName, MetricValue, MetricTime)
								} else {
									fmt.Fprintf(w, "%s{%s} %s %s\n", MetricName, MetricLabels, MetricValue, MetricTime)
								}
							}
						}

						j = -1
					}
					if read_err != nil || i == 0 {
						break
					}
				}
				if LatestTime > 0 {
					fmt.Fprintf(w, "prom_collector_latency_seconds %f %s\n",
						float64(prom.Time.UnixNano()/1e6-LatestTime)/1e3, prom.TimeStr)
				}
				fmt.Fprintf(w, "prom_collector_metric_count %d %s\n", CountMetric, prom.TimeStr)
				fmt.Fprintf(w, "prom_collector_invalid_count %d %s\n", CountInvalid, prom.TimeStr)
				fmt.Fprintf(w, "prom_collector_filtered_count %d %s\n", CountFiltered, prom.TimeStr)
				fmt.Fprintf(w, "# EOF\n")

				if compressed {
					//gzipWriter.Flush()
					gzipWriter.Close()
				} else {
					bufWriter.Flush()
				}
				f.Close()

				if debug {
					log.Println("updating data file", dataPath, "from tmp file")
				}
				err = os.Rename(dataTmp, dataPath)
				if err != nil {
					log.Println("Error renaming data file", err)
					os.Remove(dataTmp)
					os.Remove(dataPath)
				}
				// Now we can update the Prom data struct since the data has been
				// saved, we don't want Prometheus to see a new target defined if the
				// data's not ready.  Update of new target json will happen within 10
				// seconds, that should be good enough
				PromsLock.Lock()
				_, promExists := Proms[prom.Hash]
				Proms[prom.Hash] = *prom
				PromsLock.Unlock()
				if !promExists {
					log.Println("New metric found", prom)
				}
				conn.Write([]byte("HTTP/1.1 200 Go, and do what is right\nTransfer-Encoding: chunked" + srv))

			}
		}(conn)
	}
}

var jsonLock sync.Mutex

func createJson() {
	jsonLock.Lock()
	defer jsonLock.Unlock()
	jsonTmp := strings.TrimSuffix(jsonPath, "json") + "tmp"
	jf, err := os.Create(jsonTmp)
	if err != nil {
		log.Println("Error: could not create json file", jsonTmp)
		return
	}
	jw := bufio.NewWriter(jf)
	tgts := []string{}
	PromsArr := make([]Prom, 0)
	PromsLock.Lock()
	for _, p := range Proms {
		PromsArr = append(PromsArr, p)
	}
	PromsLock.Unlock()
	// sort our list of Proms by path
	sort.SliceStable(PromsArr, func(i, j int) bool {
		return PromsArr[i].Path < PromsArr[j].Path
	})
	for _, p := range PromsArr {
		//lbls := []string{}
		//for l, v := range p.LabelMap {
		//	lbls = append(lbls, fmt.Sprintf("%q:%q", l, v))
		//}
		jsonString, _ := json.Marshal(p.LabelMap)
		//tgts = append(tgts, fmt.Sprintf("{\"labels\":{%s},\"targets\": [%q]}", strings.Join(lbls, ","), p.Path))
		slash := ""
		if p.UseEndpoint {
			slash = "/"
		}
		tgts = append(tgts, fmt.Sprintf("{\"labels\":%s,\"targets\": [%q]}", jsonString, "-"+p.Path[1:]+slash))
	}
	fmt.Fprintf(jw, "[%s]", strings.Join(tgts, ","))
	jw.Flush()
	jf.Close()
	err = os.Rename(jsonTmp, jsonPath)
	if err != nil {
		log.Println("Error renaming json file", err)
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

/*func checkLabel(lbl string) bool {
	matched, err := regexp.Match(`^[a-zA-Z_][a-zA-Z0-9_]*$`, []byte(lbl))
	if err != nil {
		return false
	}
	return matched
}
func jsonEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	s := string(b)
	return s[1 : len(s)-1]
}*/

func prom_getparts(line string, path_parts map[string]string) (string, string, string, string, string) {
	// returns all strings: metrics, labels, value, time, err
	labels_map := make(map[string]string)
	labels := ""
	metric := ""
	labels_start := strings.IndexByte(line, '{')
	labels_end := 0
	prom_err := ""

	for k, v := range path_parts {
		labels_map[k] = v
	}

	//log.Println(path)
	if labels_start > 0 {
		// parse the labels
		labels_end = strings.LastIndexByte(line, '}')
		if labels_end < labels_start {
			return "", "", "", "", fmt.Sprintf("BAD LABEL SECTION CLOSURE: %s", line)
		}
		metric = line[0:labels_start]
		/*
			metric_api := -1
			metric_api_url := ""
			for i := 0; i < len(api_trigger_metric); i++ {
				if metric == api_trigger_metric[i] {
					metric_api = i
					break
				}
			}
			if metric_api >= 0 {
				metric_api_url = api_json_url[metric_api]
				log.Println(metric_api_url)
			}*/

		label_var := ""
		label_val := ""
		label_part := 0
		label_parti := labels_start + 1

		for i := labels_start + 1; i < labels_end; i++ {
			switch label_part {
			case 0:
				if line[i-1:i+1] == "=\"" {
					label_var = line[label_parti : i-1]
					label_part++
					label_parti = i + 1
				}
			case 1:
				if line[i] == '"' && line[i-1:i+1] != "\\\"" {
					label_val = line[label_parti:i]
					label_part++
					label_parti = i + 1
					if check_label_name(label_var) {
						if _, ok := path_parts[label_var]; !ok {
							labels_map[label_var] = label_val
						}
					} else {
						prom_err = fmt.Sprintf("%s  BAD LABEL (%s)", prom_err, label_var)
					}
				}
			case 2:
				if line[i] == ',' {
					label_part = 0
					label_parti = i + 1
				} else {
					label_part = 0
					prom_err = fmt.Sprintf("%s  LABEL ISSUE", prom_err)
				}
			}
		}

	} else {
		labels_end = strings.IndexAny(line, " \t")
		if labels_end < 2 {
			return "", "", "", "", fmt.Sprintf("BAD VALUE SECTION: %s", line)
		}
		metric = line[0:labels_end]
	}

	for k, v := range labels_map {
		labels = fmt.Sprintf("%s,%s=%q", labels, k, v)
	}
	labels = strings.TrimLeft(labels, ",")

	if !check_metric_name(metric) {
		return "", "", "", "", fmt.Sprintf("BAD METRIC NAME: %s", line)
	}

	value_time := strings.SplitN(strings.TrimSpace(line[labels_end+1:]), " ", 2)

	value := value_time[0]
	_, err := strconv.ParseFloat(value, 32)
	if err != nil {
		return "", "", "", "", fmt.Sprintf("BAD SAMPLE VALUE: %s", line)
	}

	time := ""
	if len(value_time) > 1 {
		time = value_time[1]
		time_val, err := strconv.Atoi(time)
		if time_val < 0 || err != nil {
			return "", "", "", "", fmt.Sprintf("BAD TIME VALUE: %s", line)
		}
	}
	//strings.TrimSpace(value_time)
	return metric, labels, value, time, prom_err
}

/*func parseLine(s string, t string) string {
	st := strings.Index(s, "{")
	if st > 0 {
		en := strings.LastIndex(s, "{")
	} else {
		p := strings.SplitN(s, " ", 2)
		lbl := p[0]
		if len(p) < 2 {
			return fmt.Sprintf("%s nan %s", lbl, t)
		}
		p = strings.SplitN(strings.TrimSpace(p[1]), " ", 2)
		if len(p) < 2 {
			return fmt.Sprintf("%s %s %s", lbl, t)
		}

	}
}*/
func check_metric_name(line string) bool {
	for i := 0; i < len(line); i++ {
		c := line[i]
		if i == 0 {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':' {
				continue
			}
			return false
		} else {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == ':' {
				continue
			}
			return false
		}
	}
	return true
}
func check_label_name(line string) bool {
	if len(line) < 1 {
		return false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if i == 0 {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
				continue
			}
			return false
		} else {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
				continue
			}
			return false
		}
	}
	return true
}
func cl(s string) string {
	return fmt.Sprintf("\nContent-Length: %d", len(s))
}
