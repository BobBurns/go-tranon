$ go get
$ go build
$ ./go-tranon <file>
$ cp output.pcapng ~/Tracefiles

****************************************** wants *****************************************

anonymize IP src/dst addresses -- working on it

sanitize applicaiton layer protocols -- working on it

gocui ncurses interface

Protocols to work on: IPv6, Ethernet, Arp, ...


***************************************** updates *****************************************

9-01-20 sanitize TELNET, surpress DNS, decode Raw and Ethernet (this was hanging me up 
capturing on tunnel interface)

9-03-20 check magic for file type pcap or pcapng and open accordingly

9-06-20 Support for IP layer working. Was trying to avoid it, but finally had to use gopacket.SerializePacket()

9-06-20 Added Command line arguments (flags). Got Ethernet MAC anonymizer working


************************************** Example Output **************************************

[bob@samadhi:go-tranon]% ./go-tranon --help
Usage of ./go-tranon:
  -A	Anonymize IP address. Requires -o old and -n new address
  -AH
    	Anonymize Hardware (MAC) address. Requires -ohaddr old and -nhaddr new address
  -P	Print supported protocols
  -S	Sanitize payload. Requires at least one -p protocol
  -naddr string
    	new quoted IPv4 or IPv6 address to anonymize
  -nhaddr string
    	new quoted MAC address to anonymize
  -oaddr string
    	old quoted IPv4 or IPv6 address to anonymize
  -ohaddr string
    	old quoted MAC address to anonymize
  -p string
    	Comma separated list of protocols to sanitize
  -q	quiet output
[bob@samadhi:go-tranon]% ./go-tranon -A -oaddr "192.168.18.140" -naddr "192.168.0.1" -S -p Telnet tel-one-packet.pcap
00000000  0a 0d 0d 0a 58 00 00 00  4d 3c 2b 1a 01 00 00 00  |....X...M<+.....|

pcapng
packet source link type Ethernet
writer link type Ethernet
before
00000000  48 4d 7e ea ef aa 00 21  d8 f5 41 7f 08 00 45 c0  |HM~....!..A...E.|
00000010  02 05 00 02 00 00 fe 06  d0 5f c0 a8 12 8c 0a 09  |........._......|
00000020  0c 94 00 17 f1 95 16 17  c1 e3 c1 ba 2a 25 50 18  |............*%P.|
00000030  0f fc 0d e4 00 00 43 0d  0a 2d 2d 2d 2d 2d 2d 2d  |......C..-------|
00000040  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000050  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000060  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000070  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000080  2d 2d 0d 0a 0d 0a 55 4e  41 55 54 48 4f 52 49 5a  |--....UNAUTHORIZ|
00000090  45 44 20 41 43 43 45 53  53 20 54 4f 20 54 48 49  |ED ACCESS TO THI|
000000a0  53 20 53 59 53 54 45 4d  20 49 53 20 50 52 4f 48  |S SYSTEM IS PROH|
000000b0  49 42 49 54 45 44 20 42  59 20 4c 41 57 0d 0a 0d  |IBITED BY LAW...|
000000c0  0a 49 46 20 59 4f 55 20  44 4f 20 4e 4f 54 20 48  |.IF YOU DO NOT H|
000000d0  41 56 45 20 50 45 52 4d  49 53 53 49 4f 4e 20 54  |AVE PERMISSION T|
000000e0  4f 20 41 43 43 45 53 53  20 54 48 49 53 20 53 59  |O ACCESS THIS SY|
000000f0  53 54 45 4d 20 59 4f 55  20 4d 55 53 54 0d 0a 4c  |STEM YOU MUST..L|
00000100  4f 47 20 4f 46 46 20 49  4d 4d 45 44 49 41 54 45  |OG OFF IMMEDIATE|
00000110  4c 59 0d 0a 0d 0a 41 4c  4c 20 41 54 54 45 4d 50  |LY....ALL ATTEMP|
00000120  54 53 20 54 4f 20 41 43  43 45 53 53 20 54 48 49  |TS TO ACCESS THI|
00000130  53 20 53 59 53 54 45 4d  20 41 52 45 20 4c 4f 47  |S SYSTEM ARE LOG|
00000140  47 45 44 0d 0a 0d 0a 46  41 49 4c 55 52 45 20 54  |GED....FAILURE T|
00000150  4f 20 43 4f 4d 50 4c 59  20 57 49 54 48 20 54 48  |O COMPLY WITH TH|
00000160  45 53 45 20 57 41 52 4e  49 4e 47 53 20 4d 41 59  |ESE WARNINGS MAY|
00000170  20 52 45 53 55 4c 54 20  49 4e 0d 0a 43 52 49 4d  | RESULT IN..CRIM|
00000180  49 4e 41 4c 20 4f 52 20  43 49 56 49 4c 20 50 52  |INAL OR CIVIL PR|
00000190  4f 53 45 43 55 54 49 4f  4e 0d 0a 0d 0a 4c 4f 47  |OSECUTION....LOG|
000001a0  20 4f 46 46 20 4e 4f 57  20 49 46 20 59 4f 55 20  | OFF NOW IF YOU |
000001b0  41 52 45 20 4e 4f 54 20  41 55 54 48 4f 52 49 5a  |ARE NOT AUTHORIZ|
000001c0  45 44 0d 0a 0d 0a 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |ED....----------|
000001d0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001e0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001f0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000200  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 0d  |---------------.|
00000210  0a 0d 0a                                          |...|

IP Layer
ip src 192.168.18.140 4
old ip src 192.168.18.140 16
found IP match
ip src 0.0.0.0 16
ip dst 10.9.12.148 4
old ip src 192.168.18.140 16
This is a TCP packet!
after
00000000  48 4d 7e ea ef aa 00 21  d8 f5 41 7f 08 00 45 c0  |HM~....!..A...E.|
00000010  02 05 00 02 00 00 fe 06  e2 ea c0 a8 00 01 0a 09  |................|
00000020  0c 94 00 17 f1 95 16 17  c1 e3 c1 ba 2a 25 50 18  |............*%P.|
00000030  0f fc 3b 98 00 00 70 61  79 6c 6f 61 64 20 72 65  |..;...payload re|
00000040  70 6c 61 63 65 64 20 62  79 20 67 6f 2d 74 72 61  |placed by go-tra|
00000050  6e 6f 6e 21 70 61 79 6c  6f 61 64 20 72 65 70 6c  |non!payload repl|
00000060  61 63 65 64 20 62 79 20  67 6f 2d 74 72 61 6e 6f  |aced by go-trano|
00000070  6e 21 70 61 79 6c 6f 61  64 20 72 65 70 6c 61 63  |n!payload replac|
00000080  65 64 20 62 79 20 67 6f  2d 74 72 61 6e 6f 6e 21  |ed by go-tranon!|
00000090  70 61 79 6c 6f 61 64 20  72 65 70 6c 61 63 65 64  |payload replaced|
000000a0  20 62 79 20 67 6f 2d 74  72 61 6e 6f 6e 21 70 61  | by go-tranon!pa|
000000b0  79 6c 6f 61 64 20 72 65  70 6c 61 63 65 64 20 62  |yload replaced b|
000000c0  79 20 67 6f 2d 74 72 61  6e 6f 6e 21 70 61 79 6c  |y go-tranon!payl|
000000d0  6f 61 64 20 72 65 70 6c  61 63 65 64 20 62 79 20  |oad replaced by |
000000e0  67 6f 2d 74 72 61 6e 6f  6e 21 70 61 79 6c 6f 61  |go-tranon!payloa|
000000f0  64 20 72 65 70 6c 61 63  65 64 20 62 79 20 67 6f  |d replaced by go|
00000100  2d 74 72 61 6e 6f 6e 21  70 61 79 6c 6f 61 64 20  |-tranon!payload |
00000110  72 65 70 6c 61 63 65 64  20 62 79 20 67 6f 2d 74  |replaced by go-t|
00000120  72 61 6e 6f 6e 21 70 61  79 6c 6f 61 64 20 72 65  |ranon!payload re|
00000130  70 6c 61 63 65 64 20 62  79 20 67 6f 2d 74 72 61  |placed by go-tra|
00000140  6e 6f 6e 21 70 61 79 6c  6f 61 64 20 72 65 70 6c  |non!payload repl|
00000150  61 63 65 64 20 62 79 20  67 6f 2d 74 72 61 6e 6f  |aced by go-trano|
00000160  6e 21 70 61 79 6c 6f 61  64 20 72 65 70 6c 61 63  |n!payload replac|
00000170  65 64 20 62 79 20 67 6f  2d 74 72 61 6e 6f 6e 21  |ed by go-tranon!|
00000180  70 61 79 6c 6f 61 64 20  72 65 70 6c 61 63 65 64  |payload replaced|
00000190  20 62 79 20 67 6f 2d 74  72 61 6e 6f 6e 21 70 61  | by go-tranon!pa|
000001a0  79 6c 6f 61 64 20 72 65  70 6c 61 63 65 64 20 62  |yload replaced b|
000001b0  79 20 67 6f 2d 74 72 61  6e 6f 6e 21 70 61 79 6c  |y go-tranon!payl|
000001c0  6f 61 64 20 72 65 70 6c  61 63 65 64 20 62 79 20  |oad replaced by |
000001d0  67 6f 2d 74 72 61 6e 6f  6e 21 70 61 79 6c 6f 61  |go-tranon!payloa|
000001e0  64 20 72 65 70 6c 61 63  65 64 20 62 79 20 67 6f  |d replaced by go|
000001f0  2d 74 72 61 6e 6f 6e 21  70 61 79 6c 6f 61 64 20  |-tranon!payload |
00000200  72 65 70 6c 61 63 65 64  20 62 79 20 67 6f 2d 74  |replaced by go-t|
00000210  72 61 6e                                          |ran|

+++++++++++++++++++++++++++
file saved as output.pcapng
[bob@samadhi:go-tranon]% ./go-tranon -AH -ohaddr "00:21:d8:f5:41:7f" -nhaddr "01:02:03:04:05:06" tel-one-packet.pcap
00000000  0a 0d 0d 0a 58 00 00 00  4d 3c 2b 1a 01 00 00 00  |....X...M<+.....|

pcapng
packet source link type Ethernet
writer link type Ethernet
before
00000000  48 4d 7e ea ef aa 00 21  d8 f5 41 7f 08 00 45 c0  |HM~....!..A...E.|
00000010  02 05 00 02 00 00 fe 06  d0 5f c0 a8 12 8c 0a 09  |........._......|
00000020  0c 94 00 17 f1 95 16 17  c1 e3 c1 ba 2a 25 50 18  |............*%P.|
00000030  0f fc 0d e4 00 00 43 0d  0a 2d 2d 2d 2d 2d 2d 2d  |......C..-------|
00000040  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000050  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000060  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000070  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000080  2d 2d 0d 0a 0d 0a 55 4e  41 55 54 48 4f 52 49 5a  |--....UNAUTHORIZ|
00000090  45 44 20 41 43 43 45 53  53 20 54 4f 20 54 48 49  |ED ACCESS TO THI|
000000a0  53 20 53 59 53 54 45 4d  20 49 53 20 50 52 4f 48  |S SYSTEM IS PROH|
000000b0  49 42 49 54 45 44 20 42  59 20 4c 41 57 0d 0a 0d  |IBITED BY LAW...|
000000c0  0a 49 46 20 59 4f 55 20  44 4f 20 4e 4f 54 20 48  |.IF YOU DO NOT H|
000000d0  41 56 45 20 50 45 52 4d  49 53 53 49 4f 4e 20 54  |AVE PERMISSION T|
000000e0  4f 20 41 43 43 45 53 53  20 54 48 49 53 20 53 59  |O ACCESS THIS SY|
000000f0  53 54 45 4d 20 59 4f 55  20 4d 55 53 54 0d 0a 4c  |STEM YOU MUST..L|
00000100  4f 47 20 4f 46 46 20 49  4d 4d 45 44 49 41 54 45  |OG OFF IMMEDIATE|
00000110  4c 59 0d 0a 0d 0a 41 4c  4c 20 41 54 54 45 4d 50  |LY....ALL ATTEMP|
00000120  54 53 20 54 4f 20 41 43  43 45 53 53 20 54 48 49  |TS TO ACCESS THI|
00000130  53 20 53 59 53 54 45 4d  20 41 52 45 20 4c 4f 47  |S SYSTEM ARE LOG|
00000140  47 45 44 0d 0a 0d 0a 46  41 49 4c 55 52 45 20 54  |GED....FAILURE T|
00000150  4f 20 43 4f 4d 50 4c 59  20 57 49 54 48 20 54 48  |O COMPLY WITH TH|
00000160  45 53 45 20 57 41 52 4e  49 4e 47 53 20 4d 41 59  |ESE WARNINGS MAY|
00000170  20 52 45 53 55 4c 54 20  49 4e 0d 0a 43 52 49 4d  | RESULT IN..CRIM|
00000180  49 4e 41 4c 20 4f 52 20  43 49 56 49 4c 20 50 52  |INAL OR CIVIL PR|
00000190  4f 53 45 43 55 54 49 4f  4e 0d 0a 0d 0a 4c 4f 47  |OSECUTION....LOG|
000001a0  20 4f 46 46 20 4e 4f 57  20 49 46 20 59 4f 55 20  | OFF NOW IF YOU |
000001b0  41 52 45 20 4e 4f 54 20  41 55 54 48 4f 52 49 5a  |ARE NOT AUTHORIZ|
000001c0  45 44 0d 0a 0d 0a 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |ED....----------|
000001d0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001e0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001f0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000200  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 0d  |---------------.|
00000210  0a 0d 0a                                          |...|

Ethernet Layer
MAC src 00:21:d8:f5:41:7f
old MAC src 00:21:d8:f5:41:7f
found MAC match
IP Layer
This is a TCP packet!
after
00000000  48 4d 7e ea ef aa 01 02  03 04 05 06 08 00 45 c0  |HM~...........E.|
00000010  02 05 00 02 00 00 fe 06  d0 5f c0 a8 12 8c 0a 09  |........._......|
00000020  0c 94 00 17 f1 95 16 17  c1 e3 c1 ba 2a 25 50 18  |............*%P.|
00000030  0f fc 0d e4 00 00 43 0d  0a 2d 2d 2d 2d 2d 2d 2d  |......C..-------|
00000040  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000050  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000060  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000070  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000080  2d 2d 0d 0a 0d 0a 55 4e  41 55 54 48 4f 52 49 5a  |--....UNAUTHORIZ|
00000090  45 44 20 41 43 43 45 53  53 20 54 4f 20 54 48 49  |ED ACCESS TO THI|
000000a0  53 20 53 59 53 54 45 4d  20 49 53 20 50 52 4f 48  |S SYSTEM IS PROH|
000000b0  49 42 49 54 45 44 20 42  59 20 4c 41 57 0d 0a 0d  |IBITED BY LAW...|
000000c0  0a 49 46 20 59 4f 55 20  44 4f 20 4e 4f 54 20 48  |.IF YOU DO NOT H|
000000d0  41 56 45 20 50 45 52 4d  49 53 53 49 4f 4e 20 54  |AVE PERMISSION T|
000000e0  4f 20 41 43 43 45 53 53  20 54 48 49 53 20 53 59  |O ACCESS THIS SY|
000000f0  53 54 45 4d 20 59 4f 55  20 4d 55 53 54 0d 0a 4c  |STEM YOU MUST..L|
00000100  4f 47 20 4f 46 46 20 49  4d 4d 45 44 49 41 54 45  |OG OFF IMMEDIATE|
00000110  4c 59 0d 0a 0d 0a 41 4c  4c 20 41 54 54 45 4d 50  |LY....ALL ATTEMP|
00000120  54 53 20 54 4f 20 41 43  43 45 53 53 20 54 48 49  |TS TO ACCESS THI|
00000130  53 20 53 59 53 54 45 4d  20 41 52 45 20 4c 4f 47  |S SYSTEM ARE LOG|
00000140  47 45 44 0d 0a 0d 0a 46  41 49 4c 55 52 45 20 54  |GED....FAILURE T|
00000150  4f 20 43 4f 4d 50 4c 59  20 57 49 54 48 20 54 48  |O COMPLY WITH TH|
00000160  45 53 45 20 57 41 52 4e  49 4e 47 53 20 4d 41 59  |ESE WARNINGS MAY|
00000170  20 52 45 53 55 4c 54 20  49 4e 0d 0a 43 52 49 4d  | RESULT IN..CRIM|
00000180  49 4e 41 4c 20 4f 52 20  43 49 56 49 4c 20 50 52  |INAL OR CIVIL PR|
00000190  4f 53 45 43 55 54 49 4f  4e 0d 0a 0d 0a 4c 4f 47  |OSECUTION....LOG|
000001a0  20 4f 46 46 20 4e 4f 57  20 49 46 20 59 4f 55 20  | OFF NOW IF YOU |
000001b0  41 52 45 20 4e 4f 54 20  41 55 54 48 4f 52 49 5a  |ARE NOT AUTHORIZ|
000001c0  45 44 0d 0a 0d 0a 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |ED....----------|
000001d0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001e0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001f0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000200  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 0d  |---------------.|
00000210  0a 0d 0a                                          |...|

+++++++++++++++++++++++++++
file saved as output.pcapng
[bob@samadhi:go-tranon]% tshark -r output.pcapng -V
Frame 1: 531 bytes on wire (4248 bits), 531 bytes captured (4248 bits) on interface intf0, id 0
    Interface id: 0 (intf0)
        Interface name: intf0
    Encapsulation type: Ethernet (1)
    Arrival Time: Sep  2, 2020 15:35:19.199157000 PDT
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1599086119.199157000 seconds
    [Time delta from previous captured frame: 0.000000000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 531 bytes (4248 bits)
    Capture Length: 531 bytes (4248 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:tcp:telnet]
Ethernet II, Src: Woonsang_04:05:06 (01:02:03:04:05:06), Dst: Dell_ea:ef:aa (48:4d:7e:ea:ef:aa)
    Destination: Dell_ea:ef:aa (48:4d:7e:ea:ef:aa)
        Address: Dell_ea:ef:aa (48:4d:7e:ea:ef:aa)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Source: Woonsang_04:05:06 (01:02:03:04:05:06)
        [Expert Info (Warning/Protocol): Source MAC must not be a group address: IEEE 802.3-2002, Section 3.2.3(b)]
            [Source MAC must not be a group address: IEEE 802.3-2002, Section 3.2.3(b)]
            [Severity level: Warning]
            [Group: Protocol]
        Address: Woonsang_04:05:06 (01:02:03:04:05:06)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
    Type: IPv4 (0x0800)
Internet Protocol Version 4, Src: 192.168.18.140, Dst: 10.9.12.148
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)
        1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    Total Length: 517
    Identification: 0x0002 (2)
    Flags: 0x0000
        0... .... .... .... = Reserved bit: Not set
        .0.. .... .... .... = Don't fragment: Not set
        ..0. .... .... .... = More fragments: Not set
    Fragment offset: 0
    Time to live: 254
    Protocol: TCP (6)
    Header checksum: 0xd05f [validation disabled]
    [Header checksum status: Unverified]
    Source: 192.168.18.140
    Destination: 10.9.12.148
Transmission Control Protocol, Src Port: 23, Dst Port: 61845, Seq: 1, Ack: 1, Len: 477
    Source Port: 23
    Destination Port: 61845
    [Stream index: 0]
    [TCP Segment Len: 477]
    Sequence number: 1    (relative sequence number)
    Sequence number (raw): 370655715
    [Next sequence number: 478    (relative sequence number)]
    Acknowledgment number: 1    (relative ack number)
    Acknowledgment number (raw): 3250203173
    0101 .... = Header Length: 20 bytes (5)
    Flags: 0x018 (PSH, ACK)
        000. .... .... = Reserved: Not set
        ...0 .... .... = Nonce: Not set
        .... 0... .... = Congestion Window Reduced (CWR): Not set
        .... .0.. .... = ECN-Echo: Not set
        .... ..0. .... = Urgent: Not set
        .... ...1 .... = Acknowledgment: Set
        .... .... 1... = Push: Set
        .... .... .0.. = Reset: Not set
        .... .... ..0. = Syn: Not set
        .... .... ...0 = Fin: Not set
        [TCP Flags: ???????AP???]
    Window size value: 4092
    [Calculated window size: 4092]
    [Window size scaling factor: -1 (unknown)]
    Checksum: 0x0de4 [unverified]
    [Checksum Status: Unverified]
    Urgent pointer: 0
    [SEQ/ACK analysis]
        [Bytes in flight: 477]
        [Bytes sent since last PSH flag: 477]
    [Timestamps]
        [Time since first frame in this TCP stream: 0.000000000 seconds]
        [Time since previous frame in this TCP stream: 0.000000000 seconds]
    TCP payload (477 bytes)
Telnet
    Data: C\r\n
    Data: -------------------------------------------------------------------------\r\n
    Data: \r\n
    Data: UNAUTHORIZED ACCESS TO THIS SYSTEM IS PROHIBITED BY LAW\r\n
    Data: \r\n
    Data: IF YOU DO NOT HAVE PERMISSION TO ACCESS THIS SYSTEM YOU MUST\r\n
    Data: LOG OFF IMMEDIATELY\r\n
    Data: \r\n
    Data: ALL ATTEMPTS TO ACCESS THIS SYSTEM ARE LOGGED\r\n
    Data: \r\n
    Data: FAILURE TO COMPLY WITH THESE WARNINGS MAY RESULT IN\r\n
    Data: CRIMINAL OR CIVIL PROSECUTION\r\n
    Data: \r\n
    Data: LOG OFF NOW IF YOU ARE NOT AUTHORIZED\r\n
    Data: \r\n
    Data: -------------------------------------------------------------------------\r\n
    Data: \r\n

[bob@samadhi:go-tranon]%

