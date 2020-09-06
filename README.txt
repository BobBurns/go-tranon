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

** Example Output **

with parameters set in main

func main() {

	// get flags first

	s := surpress{
		DNS:    true,
		output: true,
	}
	m := modify{

		Telnet:   true,
		IP:       true,
		NewSrcIP: []byte{10, 0, 0, 1},
		OldSrcIP: []byte{10, 9, 4, 80},
	}

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

[bob@samadhi:go-tranon]% ./go-tranon one-cs-tel.pcapng
00000000  0a 0d 0d 0a c8 00 00 00  4d 3c 2b 1a 01 00 00 00  |........M<+.....|

pcapng
packet source link type Null
writer link type Null
before
00000000  02 00 00 00 45 c0 02 05  ef 57 00 00 fe 06 ab 86  |....E....W......|
00000010  0a 09 04 50 0a 08 06 f4  00 17 e8 e8 c6 dc b3 1a  |...P............|
00000020  51 03 07 88 50 18 10 05  cb 86 00 00 0d 0a 2d 2d  |Q...P.........--|
00000030  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000040  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000050  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000060  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000070  2d 2d 2d 2d 2d 2d 2d 0d  0a 0d 0a 55 4e 41 55 54  |-------....UNAUT|
00000080  48 4f 52 49 5a 45 44 20  41 43 43 45 53 53 20 54  |HORIZED ACCESS T|
00000090  4f 20 54 48 49 53 20 53  59 53 54 45 4d 20 49 53  |O THIS SYSTEM IS|
000000a0  20 50 52 4f 48 49 42 49  54 45 44 20 42 59 20 4c  | PROHIBITED BY L|
000000b0  41 57 0d 0a 0d 0a 49 46  20 59 4f 55 20 44 4f 20  |AW....IF YOU DO |
000000c0  4e 4f 54 20 48 41 56 45  20 50 45 52 4d 49 53 53  |NOT HAVE PERMISS|
000000d0  49 4f 4e 20 54 4f 20 41  43 43 45 53 53 20 54 48  |ION TO ACCESS TH|
000000e0  49 53 20 53 59 53 54 45  4d 20 59 4f 55 20 4d 55  |IS SYSTEM YOU MU|
000000f0  53 54 0d 0a 4c 4f 47 20  4f 46 46 20 49 4d 4d 45  |ST..LOG OFF IMME|
00000100  44 49 41 54 45 4c 59 0d  0a 0d 0a 41 4c 4c 20 41  |DIATELY....ALL A|
00000110  54 54 45 4d 50 54 53 20  54 4f 20 41 43 43 45 53  |TTEMPTS TO ACCES|
00000120  53 20 54 48 49 53 20 53  59 53 54 45 4d 20 41 52  |S THIS SYSTEM AR|
00000130  45 20 4c 4f 47 47 45 44  0d 0a 0d 0a 46 41 49 4c  |E LOGGED....FAIL|
00000140  55 52 45 20 54 4f 20 43  4f 4d 50 4c 59 20 57 49  |URE TO COMPLY WI|
00000150  54 48 20 54 48 45 53 45  20 57 41 52 4e 49 4e 47  |TH THESE WARNING|
00000160  53 20 4d 41 59 20 52 45  53 55 4c 54 20 49 4e 20  |S MAY RESULT IN |
00000170  0d 0a 43 52 49 4d 49 4e  41 4c 20 4f 52 20 43 49  |..CRIMINAL OR CI|
00000180  56 49 4c 20 50 52 4f 53  45 43 55 54 49 4f 4e 0d  |VIL PROSECUTION.|
00000190  0a 0d 0a 4c 4f 47 20 4f  46 46 20 4e 4f 57 20 49  |...LOG OFF NOW I|
000001a0  46 20 59 4f 55 20 41 52  45 20 4e 4f 54 20 41 55  |F YOU ARE NOT AU|
000001b0  54 48 4f 52 49 5a 45 44  0d 0a 0d 0a 2d 2d 2d 2d  |THORIZED....----|
000001c0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001d0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001e0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
000001f0  2d 2d 2d 2d 2d 2d 2d 2d  2d 2d 2d 2d 2d 2d 2d 2d  |----------------|
00000200  2d 2d 2d 2d 2d 0d 0a 0d  0a                       |-----....|

IP Layer
ip src 10.9.4.80 4
old ip src [10 9 4 80] 4
found IP match
ip src 10.0.0.1 4
This is a TCP packet!
after
00000000  02 00 00 00 45 c0 02 05  ef 57 00 00 fe 06 af de  |....E....W......|
00000010  0a 00 00 01 0a 08 06 f4  00 17 e8 e8 c6 dc b3 1a  |................|
00000020  51 03 07 88 50 18 10 05  f1 dd 00 00 70 61 79 6c  |Q...P.......payl|
00000030  6f 61 64 20 72 65 70 6c  61 63 65 64 20 62 79 20  |oad replaced by |
00000040  67 6f 2d 74 72 61 6e 6f  6e 21 70 61 79 6c 6f 61  |go-tranon!payloa|
00000050  64 20 72 65 70 6c 61 63  65 64 20 62 79 20 67 6f  |d replaced by go|
00000060  2d 74 72 61 6e 6f 6e 21  70 61 79 6c 6f 61 64 20  |-tranon!payload |
00000070  72 65 70 6c 61 63 65 64  20 62 79 20 67 6f 2d 74  |replaced by go-t|
00000080  72 61 6e 6f 6e 21 70 61  79 6c 6f 61 64 20 72 65  |ranon!payload re|
00000090  70 6c 61 63 65 64 20 62  79 20 67 6f 2d 74 72 61  |placed by go-tra|
000000a0  6e 6f 6e 21 70 61 79 6c  6f 61 64 20 72 65 70 6c  |non!payload repl|
000000b0  61 63 65 64 20 62 79 20  67 6f 2d 74 72 61 6e 6f  |aced by go-trano|
000000c0  6e 21 70 61 79 6c 6f 61  64 20 72 65 70 6c 61 63  |n!payload replac|
000000d0  65 64 20 62 79 20 67 6f  2d 74 72 61 6e 6f 6e 21  |ed by go-tranon!|
000000e0  70 61 79 6c 6f 61 64 20  72 65 70 6c 61 63 65 64  |payload replaced|
000000f0  20 62 79 20 67 6f 2d 74  72 61 6e 6f 6e 21 70 61  | by go-tranon!pa|
00000100  79 6c 6f 61 64 20 72 65  70 6c 61 63 65 64 20 62  |yload replaced b|
00000110  79 20 67 6f 2d 74 72 61  6e 6f 6e 21 70 61 79 6c  |y go-tranon!payl|
00000120  6f 61 64 20 72 65 70 6c  61 63 65 64 20 62 79 20  |oad replaced by |
00000130  67 6f 2d 74 72 61 6e 6f  6e 21 70 61 79 6c 6f 61  |go-tranon!payloa|
00000140  64 20 72 65 70 6c 61 63  65 64 20 62 79 20 67 6f  |d replaced by go|
00000150  2d 74 72 61 6e 6f 6e 21  70 61 79 6c 6f 61 64 20  |-tranon!payload |
00000160  72 65 70 6c 61 63 65 64  20 62 79 20 67 6f 2d 74  |replaced by go-t|
00000170  72 61 6e 6f 6e 21 70 61  79 6c 6f 61 64 20 72 65  |ranon!payload re|
00000180  70 6c 61 63 65 64 20 62  79 20 67 6f 2d 74 72 61  |placed by go-tra|
00000190  6e 6f 6e 21 70 61 79 6c  6f 61 64 20 72 65 70 6c  |non!payload repl|
000001a0  61 63 65 64 20 62 79 20  67 6f 2d 74 72 61 6e 6f  |aced by go-trano|
000001b0  6e 21 70 61 79 6c 6f 61  64 20 72 65 70 6c 61 63  |n!payload replac|
000001c0  65 64 20 62 79 20 67 6f  2d 74 72 61 6e 6f 6e 21  |ed by go-tranon!|
000001d0  70 61 79 6c 6f 61 64 20  72 65 70 6c 61 63 65 64  |payload replaced|
000001e0  20 62 79 20 67 6f 2d 74  72 61 6e 6f 6e 21 70 61  | by go-tranon!pa|
000001f0  79 6c 6f 61 64 20 72 65  70 6c 61 63 65 64 20 62  |yload replaced b|
00000200  79 20 67 6f 2d 74 72 61  6e                       |y go-tran|

+++++++++++++++++++++++++++
file saved as output.pcapng
[bob@samadhi:go-tranon]% tshark -r output.pcapng -Vx
Frame 1: 521 bytes on wire (4168 bits), 521 bytes captured (4168 bits) on interface intf0, id 0
    Interface id: 0 (intf0)
        Interface name: intf0
    Encapsulation type: NULL/Loopback (15)
    Arrival Time: Aug 31, 2020 19:06:55.671592000 PDT
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1598926015.671592000 seconds
    [Time delta from previous captured frame: 0.000000000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 521 bytes (4168 bits)
    Capture Length: 521 bytes (4168 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: null:ip:tcp:telnet]
Null/Loopback
    Family: IP (2)
Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.8.6.244
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)
        1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    Total Length: 517
    Identification: 0xef57 (61271)
    Flags: 0x0000
        0... .... .... .... = Reserved bit: Not set
        .0.. .... .... .... = Don't fragment: Not set
        ..0. .... .... .... = More fragments: Not set
    Fragment offset: 0
    Time to live: 254
    Protocol: TCP (6)
    Header checksum: 0xafde [validation disabled]
    [Header checksum status: Unverified]
    Source: 10.0.0.1
    Destination: 10.8.6.244
Transmission Control Protocol, Src Port: 23, Dst Port: 59624, Seq: 1, Ack: 1, Len: 477
    Source Port: 23
    Destination Port: 59624
    [Stream index: 0]
    [TCP Segment Len: 477]
    Sequence number: 1    (relative sequence number)
    Sequence number (raw): 3336352538
    [Next sequence number: 478    (relative sequence number)]
    Acknowledgment number: 1    (relative ack number)
    Acknowledgment number (raw): 1359153032
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
    Window size value: 4101
    [Calculated window size: 4101]
    [Window size scaling factor: -1 (unknown)]
    Checksum: 0xf1dd [unverified]
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
    Data [truncated]: payload replaced by go-tranon!payload replaced by go-tranon!payload replaced by go-tranon!payload replaced by go-tranon!payload replaced by go-tranon!payload replaced by go-tranon!payload replaced by go-tranon!payload re

0000  02 00 00 00 45 c0 02 05 ef 57 00 00 fe 06 af de   ....E....W......
0010  0a 00 00 01 0a 08 06 f4 00 17 e8 e8 c6 dc b3 1a   ................
0020  51 03 07 88 50 18 10 05 f1 dd 00 00 70 61 79 6c   Q...P.......payl
0030  6f 61 64 20 72 65 70 6c 61 63 65 64 20 62 79 20   oad replaced by
0040  67 6f 2d 74 72 61 6e 6f 6e 21 70 61 79 6c 6f 61   go-tranon!payloa
0050  64 20 72 65 70 6c 61 63 65 64 20 62 79 20 67 6f   d replaced by go
0060  2d 74 72 61 6e 6f 6e 21 70 61 79 6c 6f 61 64 20   -tranon!payload
0070  72 65 70 6c 61 63 65 64 20 62 79 20 67 6f 2d 74   replaced by go-t
0080  72 61 6e 6f 6e 21 70 61 79 6c 6f 61 64 20 72 65   ranon!payload re
0090  70 6c 61 63 65 64 20 62 79 20 67 6f 2d 74 72 61   placed by go-tra
00a0  6e 6f 6e 21 70 61 79 6c 6f 61 64 20 72 65 70 6c   non!payload repl
00b0  61 63 65 64 20 62 79 20 67 6f 2d 74 72 61 6e 6f   aced by go-trano
00c0  6e 21 70 61 79 6c 6f 61 64 20 72 65 70 6c 61 63   n!payload replac
00d0  65 64 20 62 79 20 67 6f 2d 74 72 61 6e 6f 6e 21   ed by go-tranon!
00e0  70 61 79 6c 6f 61 64 20 72 65 70 6c 61 63 65 64   payload replaced
00f0  20 62 79 20 67 6f 2d 74 72 61 6e 6f 6e 21 70 61    by go-tranon!pa
0100  79 6c 6f 61 64 20 72 65 70 6c 61 63 65 64 20 62   yload replaced b
0110  79 20 67 6f 2d 74 72 61 6e 6f 6e 21 70 61 79 6c   y go-tranon!payl
0120  6f 61 64 20 72 65 70 6c 61 63 65 64 20 62 79 20   oad replaced by
0130  67 6f 2d 74 72 61 6e 6f 6e 21 70 61 79 6c 6f 61   go-tranon!payloa
0140  64 20 72 65 70 6c 61 63 65 64 20 62 79 20 67 6f   d replaced by go
0150  2d 74 72 61 6e 6f 6e 21 70 61 79 6c 6f 61 64 20   -tranon!payload
0160  72 65 70 6c 61 63 65 64 20 62 79 20 67 6f 2d 74   replaced by go-t
0170  72 61 6e 6f 6e 21 70 61 79 6c 6f 61 64 20 72 65   ranon!payload re
0180  70 6c 61 63 65 64 20 62 79 20 67 6f 2d 74 72 61   placed by go-tra
0190  6e 6f 6e 21 70 61 79 6c 6f 61 64 20 72 65 70 6c   non!payload repl
01a0  61 63 65 64 20 62 79 20 67 6f 2d 74 72 61 6e 6f   aced by go-trano
01b0  6e 21 70 61 79 6c 6f 61 64 20 72 65 70 6c 61 63   n!payload replac
01c0  65 64 20 62 79 20 67 6f 2d 74 72 61 6e 6f 6e 21   ed by go-tranon!
01d0  70 61 79 6c 6f 61 64 20 72 65 70 6c 61 63 65 64   payload replaced
01e0  20 62 79 20 67 6f 2d 74 72 61 6e 6f 6e 21 70 61    by go-tranon!pa
01f0  79 6c 6f 61 64 20 72 65 70 6c 61 63 65 64 20 62   yload replaced b
0200  79 20 67 6f 2d 74 72 61 6e                        y go-tran

[bob@samadhi:go-tranon]%

