# Prom-Collector
This app solves the problem of connectivity, say you have a promethues database in a firewall protected area and need to bring the metrics home for doing wholistic system measurements.  Enter Prom-Collector, with the ability to run a prom-satellite at each site and specify the local resource to expose to the promethues collector, you will never need to open another port in a firewall again!

# Why would I care to use this?  Should you need to...
* Collect metrics behind a firewall and/or network address translator?  No problem!
* Monitor the infrastructure behind a one-way http-proxy with no connections going in to said infrastructure, even with outgoing port blocks, SNI limits, and TCP session timeouts
* Implement the highest SSL standards for site to site monitoring, to ensure security in metrics transferred, upgrading any http endpoint
* Inter-connect IPv4 to IPv6 or vice versa, no limitation of port forwarding to which IP implementation used
* Upgrade a client to a newer version of TLS or enable TLS on an app without TLS support - point the app to this app configured as an HTTP endpoint and outgoing becomes TLS
* Fix MTU issues across network boundary / boundaries - repackage the packets on the fly without the client needing to "find" the correct MTU, allow the network interface to dictate this
* Automate certificate rotations on outgoing connections when the client apps cannot be taken offline / continuity of operations - make a self signed long term cert and then rotate the cert with this

# Usage
Setup the prom-collector at a central location and allow incoming connections to the collector, either by opening the TCP port or using a revers proxy such as Nginx or HAProxy.
```
./prom-collector
```

To specify a new or change the json output (for the proemetheus scrape), use:
```
$ ./prom-collector -h
Prometheus Collector, written by Paul Schou (github.com/pschou/prom-collector) in December 2020
Provided AS-IS, not responsible for loss, see LICENSE.  Usage implies agreement. (Version: 0.1.20230328.1106)

Usage: ./prom-collector [options...]

Options:
  --compress          Turn on gzip compression
  --debug             Verbose output
  --exclude-metric REGEX  Metric filter for removing metric from dump  (Default: "")
  --exclude-path REGEX  Path filter for removing metric push endpoints  (Default: "")
  --json JSON_FILE    Path into which to put all the prometheus endpoints for polling
                        (Default: "/dev/shm/metrics.json")
  --listen HOST:PORT  Listen address for metrics  (Default: ":9550")
  --only-localnet     Allow reading of metrics by localnet endpoints (ie: 192.168/16, 172.16/20, 10/8)
  --path DIRECTORY    Path into which to put the prometheus data  (Default: "/dev/shm/collector")
  --prefix URL_PREFIX  Used for all incoming requests, useful for a reverse proxy endpoint
                        (Default: "/collector")
  --secure-server BOOL  Enforce TLS 1.2+ on server side  (Default: true)
  --tls BOOL          Enable listener TLS  (Default: false)
  --verify-server BOOL  Verify or disable server certificate check  (Default: true)
Certificate options:
  --ca FILE           File to load with ROOT CAs - reloaded every minute by adding any new entries
                        (Default: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
  --cert FILE         File to load with CERT - automatically reloaded every minute
                        (Default: "/etc/pki/server.pem")
  --ciphers LIST      List of ciphers to enable  (Default: "RSA_WITH_AES_128_GCM_SHA256, RSA_WITH_AES_256_GCM_SHA384, ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ECDHE_RSA_WITH_AES_128_GCM_SHA256, ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, ECDHE_RSA_WITH_AES_256_GCM_SHA384, ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
  --hsts TIME         HSTS expiration time  (Default: 10m0s)
  --key FILE          File to load with KEY - automatically reloaded every minute
                        (Default: "/etc/pki/server.pem")

Available ciphers to pick from:
        # TLS 1.0 - 1.2 cipher suites.
        RSA_WITH_RC4_128_SHA
        RSA_WITH_3DES_EDE_CBC_SHA
        RSA_WITH_AES_128_CBC_SHA
        RSA_WITH_AES_256_CBC_SHA
        RSA_WITH_AES_128_CBC_SHA256
        RSA_WITH_AES_128_GCM_SHA256
        RSA_WITH_AES_256_GCM_SHA384
        ECDHE_ECDSA_WITH_RC4_128_SHA
        ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        ECDHE_RSA_WITH_RC4_128_SHA
        ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        ECDHE_RSA_WITH_AES_128_CBC_SHA
        ECDHE_RSA_WITH_AES_256_CBC_SHA
        ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        ECDHE_RSA_WITH_AES_128_CBC_SHA256
        ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

        # TLS 1.3 cipher suites.
        AES_128_GCM_SHA256
        AES_256_GCM_SHA384
        CHACHA20_POLY1305_SHA256
```

On the satellite system run
```
./prom-satellite -collector https://my.collector.url/site/my_site/system/my_test_system -target http://prometheus/
```

The flags available for prom-satellite are:
```
$ ./prom-satellite -h
Prometheus Satellite, written by Paul Schou (github.com/pschou/prom-collector) in December 2020
Prsonal use only, provided AS-IS -- not responsible for loss.
Usage implies agreement.

Usage: ./prom-satellite: [options...]

Options:
--ca FILE              File to load with ROOT CAs - reloaded every minute by adding any new entries
                         (Default: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
--cert FILE            File to load with CERT - automatically reloaded every minute
                         (Default: "/etc/pki/server.pem")
--collector URL        Remote listen URL for connector  (Default: "http://localhost:9550/instance/test")
--debug                Verbose output
--http-proxy PROXY-URL  Proxy for establishing connections to prom-collector  (Default: "")
--key FILE             File to load with KEY - automatically reloaded every minute
                         (Default: "/etc/pki/server.pem")
--method METHOD        Method to use to connect to collector  (Default: "GET")
--secure-collector BOOL  Enforce TLS 1.2+ on server side  (Default: true)
--secure-target BOOL   Enforce TLS 1.2+ on client side  (Default: true)
--target URL           Local endpoint to tunnel the collector to  (Default: "http://localhost/")
--threads NUM          Number of concurrent tcp streams to run to improve performance  (Default: 3)
--verify-collector BOOL  Verify or disable server certificate check, used to ignore SAN  (Default: true)
--verify-target BOOL   Verify or disable client certificate check, used to ignore SAN  (Default: true)
```

If your boxes that need to be monitored are behind a firewall that prevents outgoing connections, you may consider implementing an http-proxy for enabling out going connections.  A good package to look into that does this is https://github.com/pschou/http-proxy .  All the best!


Inside the prometheus.yml config file, you'll want to include the section
```
- job_name: collector
  scheme: http
  file_sd_configs:
    - files:
      - /dev/shm/metrics.json
  honor_labels: true
  scrape_interval: 4m
  relabel_configs:
    - source_labels: [__address__]
      regex: /*../([^/]*)
      target_label: instance
      replacement: "${1}"
    - source_labels: [__address__]
      regex: /*(.*)
      target_label: __metrics_path__
      replacement: "/collector/-${1}"
    - source_labels: []
      regex: .*
      target_label: __address__
      replacement: "localhost:9550"
```
      
