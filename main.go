package main

/* new gt.go */

/* Inspired by Jasper's Tracewrangler this is
   a simple program to anonymise TCP or UDP payloads.
   Relies heavily on go-packet, and much copy pasting
   from dev-dungeon tutorials :)
*/

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

var (
	handle             *pcap.Handle
	err                error
	paystring          = []byte("payload replaced by go-tranon!")
	supportedProtocols = []string{"TCP", "UDP", "Telnet", "HTTP", "FTP", "SMB"}
)

type surpress struct {
	DNS    bool
	output bool
}
type modify struct {
	Anon       bool
	AnonEth    bool
	Sani       bool
	IP         bool
	TCP        bool
	UDP        bool
	Telnet     bool
	HTTP       bool
	FTP        bool
	SMB        bool
	NewIpAddr  net.IP
	OldIpAddr  net.IP
	NewMacAddr net.HardwareAddr
	OldMacAddr net.HardwareAddr
}
type iflags struct {
	ipv4 bool
	ipv6 bool
	tcp  bool
	udp  bool
}

func printhd(out bool, p []byte, title string) {

	if out == false {
		fmt.Println(title)
		fmt.Println(hex.Dump(p))
	}
}

func buildPayload(newPayload []byte) {
	j := len(paystring)
	for i := 0; i < len(newPayload); i++ {
		newPayload[i] = paystring[i%j]
	}

}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	// get flags first
	anonf := flag.Bool("A", false, "Anonymize IP address. Requires -o old and -n new address")
	anonhf := flag.Bool("AH", false, "Anonymize Hardware (MAC) address. Requires -ohaddr old and -nhaddr new address")
	sanf := flag.Bool("S", false, "Sanitize payload. Requires at least one -p protocol")
	protof := flag.String("p", "", "Comma separated list of protocols to sanitize")
	printPf := flag.Bool("P", false, "Print supported protocols")
	oaddrf := flag.String("oaddr", "", "old quoted IPv4 or IPv6 address to anonymize")
	naddrf := flag.String("naddr", "", "new quoted IPv4 or IPv6 address to anonymize")
	ohaddrf := flag.String("ohaddr", "", "old quoted MAC address to anonymize")
	nhaddrf := flag.String("nhaddr", "", "new quoted MAC address to anonymize")
	//	surpf := flag.String("s", "", "Comma separated list of protocols to surpress being sanitized")
	quietf := flag.Bool("q", false, "quiet output")

	flag.Parse()

	if *printPf {
		fmt.Println("Currently Supported protocols for sanitizing:")
		for _, prot := range supportedProtocols {
			fmt.Println(prot)
		}
		os.Exit(0)
	}

	s := surpress{
		output: *quietf,
	}
	m := modify{
		Anon:    *anonf,
		AnonEth: *anonhf,
		Sani:    *sanf,
	}

	// get Annon Addresses
	if m.Anon {
		if net.ParseIP(*naddrf) != nil {
			m.NewIpAddr = net.ParseIP(*naddrf)
		}
		if net.ParseIP(*oaddrf) != nil {

			m.OldIpAddr = net.ParseIP(*oaddrf)
		}
	}
	if m.NewIpAddr.String() == "" || m.OldIpAddr.String() == "" {
		fmt.Println("WARNING. New and/or old Ip address empty")
		fmt.Println("New", m.NewIpAddr, "Old", m.OldIpAddr)
	}
	if m.AnonEth {
		addr, err := net.ParseMAC(*nhaddrf)
		checkErr(err)
		m.NewMacAddr = addr
		maddr, err := net.ParseMAC(*ohaddrf)
		checkErr(err)
		m.OldMacAddr = maddr
	}

	protos := strings.Split(*protof, ",")
	/*
		type modify struct {
			Anon       bool
			AnonEth    bool
			Sani       bool
			IP         bool

			TCP        bool
			UDP        bool
			Telnet     bool
	*/

	for _, prot := range protos {
		switch prot {
		case "Telnet":
			m.Telnet = true
		case "HTTP":
			m.HTTP = true
		case "FTP":
			m.FTP = true
		case "SMB":
			m.SMB = true
		case "IP":
			m.IP = true
		case "TCP":
			m.TCP = true
		case "UDP":
			m.UDP = true
		}
	}

	fargs := flag.Args()
	if len(fargs) != 1 {
		fmt.Printf("Usage: %s <options> <file>\n", os.Args[0])
		fmt.Printf("Use ./%s --help for list of options", os.Args[0])
		os.Exit(-1)
	}
	pcapFile := fargs[0]
	// Open input file

	// check file type
	pf, err := os.Open(pcapFile)
	if err != nil {
		panic(err)
	}
	fbytes := make([]byte, 16)
	n, err := io.ReadAtLeast(pf, fbytes, 16)
	if err != nil || n < 16 {
		log.Fatal("bad file", err)
	}

	fmt.Println(hex.Dump(fbytes))
	magic1 := []byte{0x1a, 0x2b, 0x3c, 0x4d}
	magic2 := []byte{0x4d, 0x3c, 0x2b, 0x1a}
	// need to close this now to open again
	pf.Close()

	pflag := false
	if bytes.Equal(fbytes[8:12], magic1) || bytes.Equal(fbytes[8:12], magic2) {
		fmt.Println("pcapng")
		pflag = true
	} else {
		fmt.Println("most likely pcap")
	}

	//os.Exit(0)

	// Open output file
	f, err := os.Create("output.pcapng")
	if err != nil {
		panic(err)
	}

	defer f.Close()
	//	w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	// Open file instead of device

	// Loop through packets in file
	//	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var lt layers.LinkType
	packetSource := &gopacket.PacketSource{}
	if pflag {
		pf, err := os.Open(pcapFile)
		if err != nil {
			panic(err)
		}
		defer pf.Close()
		r, err := pcapgo.NewNgReader(pf, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			panic(err)
		}

		lt = r.LinkType()

		packetSource = gopacket.NewPacketSource(r, lt)
	} else {

		handle, err = pcap.OpenOffline(pcapFile)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		lt = handle.LinkType()
		packetSource = gopacket.NewPacketSource(handle, lt)
	}
	fmt.Println("packet source link type", lt)
	fmt.Println("writer link type", lt)
	w, err := pcapgo.NewNgWriter(f, lt)

	if err != nil {
		panic(err)
	}
	defer w.Flush()

	// Loop packets
	i := 0
	for packet := range packetSource.Packets() {
		printhd(s.output, packet.Data(), "before")
		i++
		flags := iflags{}
		// buffer for new packet
		newBuffer := gopacket.NewSerializeBuffer()
		// Layer 2
		EthLayer := packet.Layer(layers.LayerTypeEthernet)
		if EthLayer == nil && m.AnonEth {
			fmt.Println("No Ethernet Layer to modify in packet %d\n", i)
		} else if m.AnonEth {
			// do something with ethernet layer
			fmt.Println("Ethernet Layer")
			eth := EthLayer.(*layers.Ethernet)
			fmt.Println("MAC src", eth.SrcMAC)
			fmt.Println("old MAC src", m.OldMacAddr)
			// IP address is at the end of 16 byte slice
			if bytes.Equal(eth.SrcMAC, m.OldMacAddr) {
				fmt.Println("found MAC match")
				eth.SrcMAC = m.NewMacAddr

			}
			if bytes.Equal(eth.DstMAC, m.OldMacAddr) {
				fmt.Println("found MAC match")
				eth.DstMAC = m.NewMacAddr

			}
		}
		// Layer 3
		ip4 := &layers.IPv4{}

		IPLayer := packet.Layer(layers.LayerTypeIPv4)
		if IPLayer == nil && m.IP {
			fmt.Println("No IP Layer to modify in packet %d\n", i)
		} else {
			// INFO need to handle IPv6 here
			flags.ipv4 = true

			fmt.Println("IP Layer")
			ip4 = IPLayer.(*layers.IPv4)
			if m.Anon {
				fmt.Println("ip src", ip4.SrcIP, len(ip4.SrcIP))
				fmt.Println("old ip src", m.OldIpAddr, len(m.OldIpAddr))
				// IP address is at the end of 16 byte slice
				if bytes.Equal(ip4.SrcIP.To4(), m.OldIpAddr.To4()) {
					fmt.Println("found IP match")
					//copy([]byte(s.NewSrcIP[0:4]), []byte(ip.SrcIP[0:4]))
					ip4.SrcIP = m.NewIpAddr
					fmt.Println("ip src", ip4.SrcIP[0:4], len(ip4.SrcIP))

				}
				fmt.Println("ip dst", ip4.DstIP, len(ip4.DstIP))
				fmt.Println("old ip src", m.OldIpAddr, len(m.OldIpAddr))
				// IP address is at the end of 16 byte slice
				if bytes.Equal(ip4.DstIP.To4(), m.OldIpAddr.To4()) {
					fmt.Println("found IP match")
					//copy([]byte(s.NewSrcIP[0:4]), []byte(ip.SrcIP[0:4]))
					ip4.DstIP = m.NewIpAddr
					fmt.Println("ip dst", ip4.DstIP[0:4], len(ip4.DstIP))

				}
			}
		}

		// Layer 4
		tcp := &layers.TCP{}
		udp := &layers.UDP{}
		// TCP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			flags.tcp = true
			fmt.Println("This is a TCP packet!")
			tcp = tcpLayer.(*layers.TCP)
			// TCP payload

			if m.TCP {
				tcpPayload := tcpLayer.LayerPayload()
				tcpNewPayload := make([]byte, len(tcpPayload))

				j := len(paystring)
				for i := 0; i < len(tcpPayload); i++ {
					tcpNewPayload[i] = paystring[i%j]
				}

				copy(tcp.BaseLayer.Payload, tcpNewPayload)
			}

			// Telnet

			tcpAppLayerPayload(m, *tcp, packet)

			/*
				if m.Telnet && (tcp.DstPort == 23 ||
					tcp.SrcPort == 23) {
					if app := packet.ApplicationLayer(); app != nil {

						telpay := app.Payload()
						if telpay[0] >= 240 {
							fmt.Println("telnet command data. skipping...")
						} else {

							appNewPayload := make([]byte, len(telpay))

							buildPayload(appNewPayload)
							copy(*packet.ApplicationLayer().(*gopacket.Payload), appNewPayload)
						}

					}

				}
			*/

			//printhd(s.output, packet.Data(), "before")

			// New Payload
			/* DONT KNOW WHY
			tcpPayload := tcpLayer.LayerPayload()
			tcpNewPayload := make([]byte, len(tcpPayload))

			j := len(paystring)
			for i := 0; i < len(tcpPayload); i++ {
				tcpNewPayload[i] = paystring[i%j]
			}

			copy(tcp.BaseLayer.Payload, tcpNewPayload)
			*/

		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			//UDP
			flags.udp = true
			fmt.Println("This is a UDP packet!")
			udp = udpLayer.(*layers.UDP)
			if s.DNS == true && (udp.DstPort == 53 ||
				udp.SrcPort == 53) {
				fmt.Println("Skipping DNS packet")
			} else if m.UDP {

				// New UDP Payload
				udpPayload := udpLayer.LayerPayload()
				udpNewPayload := make([]byte, len(udpPayload))

				j := len(paystring)
				for i := 0; i < len(udpPayload); i++ {
					udpNewPayload[i] = paystring[i%j]
				}

				copy(udp.BaseLayer.Payload, udpNewPayload)
			}

		}
		// serialize and write packet here
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}

		// just a test
		if flags.tcp {
			// what to do here when ipv6?
			tcp.SetNetworkLayerForChecksum(ip4)
		} else if flags.udp {
			udp.SetNetworkLayerForChecksum(ip4)

		} else {
			//	fmt.Println("not a tcp packet so cannot compute checksum")
			fmt.Println("no udp or tcp layer. rut ro")
			// write it anyway
		}
		err := gopacket.SerializePacket(newBuffer, opts, packet)
		if err != nil {
			log.Fatal(err)
		}
		printhd(s.output, newBuffer.Bytes(), "after")
		// old

		// write new buffer bytes
		w.WritePacket(packet.Metadata().CaptureInfo, newBuffer.Bytes())
		//			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	} // end packet loop

	fmt.Println("+++++++++++++++++++++++++++")
	fmt.Println("file saved as output.pcapng")
}
