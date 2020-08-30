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

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <file>\n", os.Args[0])
		os.Exit(-1)
	}
	pcapFile := os.Args[1]
	// Open output file
	f, _ := os.Create("output.pcapng")
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		panic(err)
	}
	//	w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	defer f.Close()
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

			packetFrameb := packet.Data()
			fmt.Println("before")
			fmt.Println(hex.Dump(packetFrameb))

			// New Payload
			tcpPayload := tcpLayer.LayerPayload()
			tcpNewPayload := make([]byte, len(tcpPayload))

			j := len(paystring)
			for i := 0; i < len(tcpPayload); i++ {
				tcpNewPayload[i] = paystring[i%j]
			}

			tcp := tcpLayer.(*layers.TCP)
			copy(tcp.BaseLayer.Payload, tcpNewPayload)

			packetFrame := packet.Data()
			//	newPacket := gopacket.NewPacket(packetFrame, layers.LayerTypeEthernet, gopacket.Default)

			fmt.Println("after")
			fmt.Println(hex.Dump(packetFrame))

			// Write Packet
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			//UDP
			fmt.Println("This is a UDP packet!")

			packetFrameb := packet.Data()
			fmt.Println("before")
			fmt.Println(hex.Dump(packetFrameb))

			// New Payload
			udpPayload := udpLayer.LayerPayload()
			udpNewPayload := make([]byte, len(udpPayload))

			j := len(paystring)
			for i := 0; i < len(udpPayload); i++ {
				udpNewPayload[i] = paystring[i%j]
			}

			udp := udpLayer.(*layers.UDP)
			copy(udp.BaseLayer.Payload, udpNewPayload)

			packetFrame := packet.Data()

			fmt.Println("after")
			fmt.Println(hex.Dump(packetFrame))

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
