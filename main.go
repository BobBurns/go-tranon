package main

/* Inspired by Jasper's Tracewrangler this is
   a simple program to anonymise TCP or UDP payloads.
   Relies heavily on go-packet, and much copy pasting
   from dev-dungeon tutorials :)
*/

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"os"
)

var (
	handle    *pcap.Handle
	err       error
	paystring = []byte("payload replaced by go-tranon!")
)

type surpress struct {
	DNS    bool
	output bool
	Telnet bool
}

func printhd(out bool, p []byte, title string) {

	if out == true {
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

func main() {

	// get flags first

	s := surpress{
		DNS:    true,
		output: true,
		Telnet: true,
	}
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <file>\n", os.Args[0])
		os.Exit(-1)
	}
	pcapFile := os.Args[1]
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
	for packet := range packetSource.Packets() {
		// TCP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")
			tcp := tcpLayer.(*layers.TCP)

			// Telnet

			if s.Telnet == true && (tcp.DstPort == 23 ||
				tcp.SrcPort == 23) {
				if app := packet.ApplicationLayer(); app != nil {

					telpay := app.Payload()
					if telpay[0] >= 240 {
						fmt.Println("telnet command data. skipping...")
						w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
						continue
					}

					printhd(true, telpay, "telnet dump")
					appNewPayload := make([]byte, len(telpay))

					buildPayload(appNewPayload)
					copy(*packet.ApplicationLayer().(*gopacket.Payload), appNewPayload)

					printhd(true, packet.Data(), "telnet dump 2")
					w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
					continue
				}

			}

			printhd(s.output, packet.Data(), "before")

			// New Payload
			tcpPayload := tcpLayer.LayerPayload()
			tcpNewPayload := make([]byte, len(tcpPayload))

			j := len(paystring)
			for i := 0; i < len(tcpPayload); i++ {
				tcpNewPayload[i] = paystring[i%j]
			}

			copy(tcp.BaseLayer.Payload, tcpNewPayload)

			printhd(s.output, packet.Data(), "after")
			// Write Packet
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			//UDP
			fmt.Println("This is a UDP packet!")
			udp := udpLayer.(*layers.UDP)
			if s.DNS == true && (udp.DstPort == 53 ||
				udp.SrcPort == 53) {
				fmt.Println("Skipping DNS packet")
				w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				continue
			}

			printhd(s.output, packet.Data(), "before")
			//if s.output == true {
			//	packetFrameb := packet.Data()
			//	fmt.Println("before")
			//	fmt.Println(hex.Dump(packetFrameb))
			//}

			// New Payload
			udpPayload := udpLayer.LayerPayload()
			udpNewPayload := make([]byte, len(udpPayload))

			j := len(paystring)
			for i := 0; i < len(udpPayload); i++ {
				udpNewPayload[i] = paystring[i%j]
			}

			copy(udp.BaseLayer.Payload, udpNewPayload)

			//		packetFrame := packet.Data()

			//		fmt.Println("after")
			//		fmt.Println(hex.Dump(packetFrame))
			printhd(s.output, packet.Data(), "after")

			// Write Packet
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		} else {
			fmt.Println("Not a TCP or UDP packet")
			// catch all
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

	}
	fmt.Println("+++++++++++++++++++++++++++")
	fmt.Println("file saved as output.pcapng")
}
