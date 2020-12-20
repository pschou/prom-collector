# Prom-Collector
This app solves the problem of connectivity, say you have a promethues database in a firewall protected area and need to bring the metrics home for doing wholistic system measurements.  Enter Prom-Collector, with the ability to run a prom-satellite at each site and specify the local resource to expose to the promethues collector, you will never need to open another port in a firewall again!

# Why would I care to use this?  Should you need to...
* Collect metrics behind a firewall and/or network address translator?  No problem!
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
 Usage of ./prom-collector:
  -ca string
        File to load with ROOT CAs - reloaded every minute by adding any new entries (default "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
  -cert string
        File to load with CERT - automatically reloaded every minute (default "/etc/pki/server.pem")
  -debug
        Verbose output
  -json string
        Path into which to put the prometheus json endpoints for polling (default "/dev/shm/metrics.json")
  -key string
        File to load with KEY - automatically reloaded every minute (default "/etc/pki/server.pem")
  -listen string
        Listen address for metrics (default ":9550")
  -path string
        Path into which to put the prometheus data (default "/dev/shm/collector")
  -prefix string
        URL prefix used upstream in reverse proxy endpoint for all incoming requests
  -secure-server
        Enforce TLS 1.2 on server side (default true)
  -tls
        Enable listener TLS (enable with -tls=true)
  -verify-server
        Verify or disable server certificate check (default true)
```

On the satellite system run
```
./prom-satellite -collector https://my.collector.url/site/my_site/system/my_test_system -target http://prometheus/
```

The flags available for prom-satellite are:
```
 Usage of ./prom-satellite:
  -ca string
        File to load with ROOT CAs - reloaded every minute by adding any new entries (default "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
  -cert string
        File to load with CERT - automatically reloaded every minute (default "/etc/pki/server.pem")
  -collector string
        Remote listen URL for connector (default "http://localhost:9550/instance/test")
  -debug
        Verbose output
  -http-proxy string
        Address for establishing connections using http-proxy CONNECT method
  -key string
        File to load with KEY - automatically reloaded every minute (default "/etc/pki/server.pem")
  -secure-collector
        Enforce TLS 1.2+ on server side (default true)
  -secure-target
        Enforce TLS 1.2+ on client side (default true)
  -target string
        Local endpoint for connector (default "http://localhost/index.html")
  -threads int
        Number of concurrent tcp streams to run to improve performance (default 3)
  -verify-collector
        Verify or disable server certificate check, -verify-collector=false to ignore SAN (default true)
  -verify-target
        Verify or disable client certificate check, -verify-target=false to ignore SAN (default true)
```

If your boxes that need to be monitored are behind a firewall that prevents outgoing connections, you may consider implementing an http-proxy for enabling out going connections.  A good package to look into that does this is https://github.com/pschou/http-proxy .  All the best!
