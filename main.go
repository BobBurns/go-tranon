package main

/* Inspired by Jasper's Tracewrangler this is
   a simple program to anonymise TCP or UDP payloads.
   Relies heavily on go-packet, and much copy pasting
   from dev-dungeon tutorials :)
*/

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
)

var (
	handle *pcap.Handle
	err    error
)

type surpress struct {
	DNS    bool
	output bool
}

func printhd(out bool, p []byte, title string) {

	if out == true {
		fmt.Println(title)
		fmt.Println(hex.Dump(p))
	}
}

func main() {

	// get flags first

	s := surpress{
		DNS:    true,
		output: false,
	}
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <file>\n", os.Args[0])
		os.Exit(-1)
	}
	pcapFile := os.Args[1]
	// Open output file
	f, err := os.Create("output.pcapng")
	if err != nil {
		panic(err)
	}

	defer f.Close()
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)

	if err != nil {
		panic(err)
	}
	defer w.Flush()
	//	w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	// Open file instead of device
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	paystring := []byte("payload replaced by go-tranon!")
	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// TCP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")

			printhd(s.output, packet.Data(), "before")
			//		packetFrameb := packet.Data()
			//		fmt.Println("before")
			//		fmt.Println(hex.Dump(packetFrameb))

			// New Payload
			tcpPayload := tcpLayer.LayerPayload()
			tcpNewPayload := make([]byte, len(tcpPayload))

			j := len(paystring)
			for i := 0; i < len(tcpPayload); i++ {
				tcpNewPayload[i] = paystring[i%j]
			}

			tcp := tcpLayer.(*layers.TCP)
			copy(tcp.BaseLayer.Payload, tcpNewPayload)

			//			packetFrame := packet.Data()
			//	newPacket := gopacket.NewPacket(packetFrame, layers.LayerTypeEthernet, gopacket.Default)

			//			fmt.Println("after")
			//			fmt.Println(hex.Dump(packetFrame))

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
