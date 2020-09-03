$ go get
$ go build
$ ./go-tranon <file>
$ cp output.pcapng ~/Tracefiles

** wants **
anonymize IP src/dst addresses
sanitize applicaiton layer protocols


** updates **
9-01-20 sanitize TELNET, surpress DNS, decode Raw and Ethernet (this was hanging me up capturing on tunnel interface)

9-03-20 check magic for file type pcap or pcapng and open accordingly

