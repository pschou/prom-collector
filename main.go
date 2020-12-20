//
//  This package was written by Paul Schou in Dec 2020
//
//  Prometheus Collector - basic end point package for sending prometheus metrics!
//
package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	//"encoding/json"
	"bufio"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"net/url"
	//"io"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	//"regexp"
	"bytes"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Prom struct {
	Path        string
	Hash        [16]byte
	Size        int
	Time        time.Time
	TimeStr     string
	LabelSlice  []string
	LabelMap    map[string]string
	useEndpoint bool
	endPoints   chan *reflector
	lastSeen    string
}
type reflector struct {
	conn      net.Conn
	close     chan int
	urlSuffix string
	urlHost   string
}

var Proms = map[[16]byte]Prom{}

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
		fmt.Fprintf(os.Stderr, "Prometheus Collector, written by Paul Schou github@paulschou.com in December 2020\nPrsonal use only, provided AS-IS -- not responsible for loss.\nUsage implies agreement.\n\n Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	var listen = flag.String("listen", ":9550", "Listen address for metrics")
	var prefix = flag.String("prefix", "", "URL prefix used upstream in reverse proxy endpoint for all incoming requests")
	var cert_file = flag.String("cert", "/etc/pki/server.pem", "File to load with CERT - automatically reloaded every minute")
	var key_file = flag.String("key", "/etc/pki/server.pem", "File to load with KEY - automatically reloaded every minute")
	var root_file = flag.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs - reloaded every minute by adding any new entries")
	var verify_server = flag.Bool("verify-server", true, "Verify or disable server certificate check")
	var secure_server = flag.Bool("secure-server", true, "Enforce TLS 1.2 on server side")
	var tls_enabled = flag.Bool("tls", false, "Enable listener TLS (enable with -tls=true)")
	var verbose = flag.Bool("debug", false, "Verbose output")
	var basepath = flag.String("path", basePath, "Path into which to put the prometheus data")
	var jsonpath = flag.String("json", jsonPath, "Path into which to put the prometheus json endpoints for polling")
	flag.Parse()

	//var err error
	debug = *verbose

	urlPrefix = strings.TrimRight(*prefix, "/")
	keyFile = *key_file
	certFile = *cert_file
	rootFile = *root_file
	rootpool = x509.NewCertPool()
	basePath = *basepath
	jsonPath = *jsonpath
	//Proms = make(map[[16]byte]Prom, 0)

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

		config.Rand = rand.Reader
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
		for now := range time.Tick(15 * time.Second) {
			if debug {
				log.Println(now, "pinging all reflectors")
			}
			for _, prom := range Proms {
				if prom.useEndpoint {
					count := len(prom.endPoints)
					for ic := 0; ic < count; ic++ {
						pass := make(chan bool, 1)

						if debug {
							log.Println("len of endpoints:", len(prom.endPoints))
						}

						//for i := 0; i < len(prom.endPoints); i++ {
						//var test_ref *reflector
						test_ref := <-prom.endPoints
						if test_ref.conn == nil {
							continue
						}
						go func() {
							buf := make([]byte, 8)
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
											prom.lastSeen = test_ref.conn.RemoteAddr().String()
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
						case <-time.After(3 * time.Second):
							// the read from ch has timed out
							if test_ref.conn != nil {
								test_ref.conn.Close()
								//test_ref.conn = nil
							}
						}

						if debug {
							log.Println("len of endpoints:", len(prom.endPoints))
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

		go func(c net.Conn) {
			defer c.Close()
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
			srv := "\nServer: Prom Collector - Written by Paul Schou github@paulschou.com; Copyright Dec 2020 - Licensed for Personal Use Only\n\n"
			headers := []string{}

			for i := 0; i < buf_size-1; i++ { // Read one charater at a time
				if _, err := c.Read(buf[i : i+1]); err != nil {
					break
				}
				if buf[i] == 0xa { // New line to parse...
					s := string(buf[0 : i+1])
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
					} else if strings.HasPrefix(s, "POST ") || strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "REFLECT ") {
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
						if urlPrefix != "" {
							if strings.HasPrefix(path, urlPrefix+"/") == false {
								c.Write([]byte("HTTP/1.1 302 Moved\nLocation: " + urlPrefix + "/" + srv))
								return
							}
							path = strings.TrimPrefix(path, urlPrefix)
						}
						if parts[0] == "REFLECT" {
							if len(parts) >= 4 {
								urlHost = strings.TrimSpace(parts[2])
								urlSuffix = strings.TrimSpace(parts[3])
							} else {
								failure = "Malformed reflect: " + s
								break
							}
						}
					} else if strings.HasPrefix(s, "Connection: ") {
					} else if i <= 1 { // end of connect request!
						break
					} else {
						headers = append(headers, s)
					}

					i = -1 // reset the buffer scanner to 0
				}
			}
			if failure != "" {
				if debug {
					log.Println("  failure: " + failure)
				}
				c.Write([]byte("HTTP/1.1 500 Error: " + failure + cl(failure) + srv + failure))
				return
			}

			// handle the get index for listing endpoints
			if method == "GET" && (path == "" || path == "/") {
				var buffer bytes.Buffer
				buffer.WriteString("<h3>List of endpoints seen:</h3>\n")
				for _, p := range Proms {
					if p.useEndpoint {
						buffer.WriteString(fmt.Sprintf("<a href=\"%s/\">%v: %v</a> - @%s %v<br>\n", p.Path[1:], p.Path[4:], p.LabelSlice, p.lastSeen, p.Time))
					} else {
						buffer.WriteString(fmt.Sprintf("<a href=\"%s\">%v: %v</a> - %v<br>\n", p.Path[1:], p.Path[4:], p.LabelSlice, p.Time))
					}
				}
				s := "Prom-Collector" + buffer.String()
				c.Write([]byte("HTTP/1.1 200 Okay" + cl(s) + ch + srv + s))
				c.Close()
				return
			}

			if method == "GET" {
				parts := strings.SplitN(path, "/", 4)
				if len(parts[1]) == 2 && len(parts[2]) == 32 {
					hash_buf := make([]byte, 16)
					hex.Decode(hash_buf, []byte(parts[2]))
					hash := [16]byte{}
					copy(hash[:], hash_buf)
					if p, ok := Proms[hash]; ok {
						if Proms[hash].useEndpoint {
							if debug {
								log.Println("Using channel connection for request")
							}
							var ref *reflector
							select {
							case ref = <-Proms[hash].endPoints:
							case <-time.After(5 * time.Second):
								return
							}

							//ref := <-Proms[hash].endPoints
							//time.Sleep(10 * time.Second)
							//if strings.HasSuffix(ref.urlSuffix, "/") && len(path) <= 36 {
							if len(path) <= 36 || len(parts) < 4 {
								Proms[hash].endPoints <- ref
								c.Write([]byte("HTTP/1.1 302 Redirect to add slash\nLocation: " + path + "/" + srv))
								return
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
							go io.Copy(c, ref.conn)
							io.Copy(ref.conn, c)
							if debug {
								log.Println("Closing connections")
							}
							ref.close <- 1
							c.Close()
							return
						}
						// If the requested hash exists, print it out
						f, err := os.Open(basePath + p.Path)
						if err == nil {
							defer f.Close()
							fi, err := f.Stat()
							if err != nil {
								failure = "Could not find " + path
							} else {
								c.Write([]byte(fmt.Sprintf("HTTP/1.1 200 As requested\nContent-Length: %d\nContent-Type: text/text; charset=UTF-8%s", fi.Size(), srv)))
								//c.Write([]byte("HTTP/1 200 As requested" + ct + srv))
								io.Copy(c, f)
								return
							}
						} else {
							failure = "Error opening metric for reading"
						}
					} else {
						failure = "Metric missing " + path
					}
				} else {
					failure = "Metric missing " + path
				}
			}

			if method == "POST" {
				if path == "" {
					failure = "Missing path, with target label value pairs"
				} else if contLen < 0 && failure == "" {
					failure = "Missing Content-Length header"
				} else if contLen < 3 && failure == "" {
					failure = "Content-Length too short for data"
				}
			}
			if failure != "" {
				c.Write([]byte("HTTP/1.1 404 Error: " + failure + cl(failure) + srv + failure))
				return
			}

			prom := &Prom{Time: time.Now(), LabelSlice: []string{}, LabelMap: make(map[string]string), useEndpoint: false}
			//prom.Time = time.Now()
			prom.TimeStr = fmt.Sprintf("%v", prom.Time.UnixNano()/1e6)
			//prom.LabelSlice = []string{}
			//prom.LabelMap = make(map[string]string)
			parts := strings.Split(strings.Trim(path[1:], "/ \r\t"), "/")
			if len(parts)%2 != 0 && failure == "" {
				failure = "Error path \"/" + strings.Trim(path[1:], "/ \r\t") + "\" must have even pairs, be in format /LABEL_1/VALUE_1/LABEL_2/VALUE_2 / ..."
			} else {
				for i := 0; i < len(parts); i = i + 2 {
					if check_label_name(parts[i]) == false || parts[i] == "" {
						failure = "Error label \"" + parts[i] + "\" in path must have valid prometheus label name"
						break
					}
					lbl := strings.TrimSpace(parts[i])
					val, err := url.QueryUnescape(strings.TrimSpace(parts[i+1]))
					if err != nil {
						failure = "Error while parsing label value in url \"" + parts[i+1] + "\""
						break
					}
					prom.LabelMap[lbl] = val
					prom.LabelSlice = append(prom.LabelSlice, fmt.Sprintf("%s=%s", lbl, fmt.Sprintf("%q", val)))
				}
			}
			if failure != "" {
				c.Write([]byte("HTTP/1.1 500 Error: " + failure + cl(failure) + srv + failure))
				return
			}
			sort.Strings(prom.LabelSlice)
			prom.Hash = md5.Sum([]byte(strings.Join(prom.LabelSlice, "\n")))
			prom.Path = fmt.Sprintf("/%x/%x", prom.Hash[0], prom.Hash)

			// Handle the reflection operation which the struct exists
			if method == "REFLECT" {
				ref := &reflector{conn: c, urlSuffix: urlSuffix, urlHost: urlHost, close: make(chan int, 1)}
				if p, ok := Proms[prom.Hash]; ok && p.useEndpoint == false {
					delete(Proms, prom.Hash)
				}
				if _, ok := Proms[prom.Hash]; !ok {
					prom.endPoints = make(chan *reflector, 10)
					prom.useEndpoint = true
					prom.lastSeen = conn.RemoteAddr().String()
					Proms[prom.Hash] = *prom
				} else {
					p := Proms[prom.Hash]
					p.Time = time.Now()
				}
				//fmt.Println("New connection from", conn.RemoteAddr())
				//Proms[prom.Hash].Time = time.Now()
				Proms[prom.Hash].endPoints <- ref
				if debug {
					log.Println("--waiting to close sub connection")
				}
				<-ref.close
				if debug {
					log.Println("--Closing sub connection")
				}
				c.Close()
				return
			}

			if failure != "" {
				c.Write([]byte("HTTP/1.1 500 Error: " + failure + cl(failure) + srv + failure))
				return
			}

			// handle the post method
			if method == "POST" {
				prom.Size = contLen
				Proms[prom.Hash] = *prom
				if cont100 {
					c.Write([]byte("HTTP/1.1 100 Continue thy ordinances\n\n"))
				}

				os.Mkdir(fmt.Sprintf("%s/%x", basePath, prom.Hash[0]), 0755)
				f, err := os.Create(basePath + prom.Path)
				if err != nil {
					log.Println("could not create file", basePath+prom.Path)
					return
				}
				defer f.Close()

				w := bufio.NewWriter(f)
				fmt.Fprintf(w, "# From %v on %v\n", c.RemoteAddr(), time.Now())
				fmt.Println("keypairs=", prom.LabelMap, "outpath", prom.LabelSlice, "hash", prom.Hash, "path", prom.Path, "proms", Proms)

				i := contLen
				for j := 0; i > 0; j++ {
					n, read_err := c.Read(buf[j : j+1])
					i = i - n
					if buf[j] == 0xa || i == 0 { //|| (j > 3 && read_err != nil) || i == 0 {
						line := strings.TrimSpace(string(buf[0:j]))

						if line == "" || strings.HasPrefix(line, "----------------") ||
							strings.HasPrefix(line, "Content-Disposition: ") || strings.HasPrefix(line, "Content-Type: ") {
							j = -1
							continue
						}
						if strings.HasPrefix(line, "#") {
							fmt.Fprintf(w, "%s\n", line)
							j = -1
							continue
						}
						MetricName, MetricLabels, MetricValue, MetricTime, MetricErr := prom_getparts(line, prom.LabelMap)
						if MetricErr != "" {
							fmt.Fprintf(w, "# %s\n", MetricErr)
						}

						if MetricTime == "" {
							MetricTime = prom.TimeStr
						}

						if MetricName != "" {
							if MetricLabels == "" {
								fmt.Fprintf(w, "%s %s %s\n", MetricName, MetricValue, MetricTime)
							} else {
								fmt.Fprintf(w, "%s{%s} %s %s\n", MetricName, MetricLabels, MetricValue, MetricTime)
							}
						}

						j = -1
					}
					if read_err != nil || i == 0 {
						break
					}
				}
				w.Flush()
				c.Write([]byte("HTTP/1.1 200 Go, and do what is right" + srv))

				jf, err := os.Create(jsonPath)
				if err != nil {
					log.Println("Error: could not create json file", jsonPath)
					return
				}
				jw := bufio.NewWriter(jf)
				tgts := []string{}
				for _, p := range Proms {
					lbls := []string{}
					for l, v := range p.LabelMap {
						lbls = append(lbls, fmt.Sprintf("%q:%q", l, v))
					}
					tgts = append(tgts, fmt.Sprintf("{\"labels\":{%s},\"targets\": [%q]}", strings.Join(lbls, ","), p.Path))
				}
				fmt.Fprintf(jw, "[%s]", strings.Join(tgts, ","))
				jw.Flush()
				defer jf.Close()
			}
		}(conn)
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
