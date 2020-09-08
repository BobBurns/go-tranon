package main

import (
	//	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func tcpAppLayerPayload(m modify, tcp layers.TCP, packet gopacket.Packet) {
	fmt.Println("App layer function")

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
	if m.HTTP && (tcp.DstPort == 80 ||
		tcp.SrcPort == 80) {
		if app := packet.ApplicationLayer(); app != nil {
			fmt.Println("reached HTTP")

			httppay := app.Payload()

			appNewPayload := make([]byte, len(httppay))

			buildPayload(appNewPayload)
			// keep first 16 bytes
			if len(httppay) > 16 {
				copy(appNewPayload[0:16], httppay[0:16])
			}
			copy(*packet.ApplicationLayer().(*gopacket.Payload), appNewPayload)

		}

	}
	if m.FTP && (tcp.DstPort == 21 ||
		tcp.SrcPort == 21) {
		if app := packet.ApplicationLayer(); app != nil {
			fmt.Println("reached FTP")

			ftppay := app.Payload()

			appNewPayload := make([]byte, len(ftppay))

			buildPayload(appNewPayload)
			// keep first 16 bytes
			if len(ftppay) > 4 {
				copy(appNewPayload[0:4], ftppay[0:4])
			}
			copy(*packet.ApplicationLayer().(*gopacket.Payload), appNewPayload)

		}

	}
	if m.SMB && (tcp.DstPort == 445 ||
		tcp.SrcPort == 445) {
		if app := packet.ApplicationLayer(); app != nil {
			fmt.Println("reached SMB")

			smbpay := app.Payload()

			appNewPayload := make([]byte, len(smbpay))

			buildPayload(appNewPayload)
			// SMB header
			if len(smbpay) > 32 {
				copy(appNewPayload[0:32], smbpay[0:32])
			}
			copy(*packet.ApplicationLayer().(*gopacket.Payload), appNewPayload)

		}
		return

	}
	if m.SMB && (tcp.DstPort == 139 ||
		tcp.SrcPort == 139) {
		if app := packet.ApplicationLayer(); app != nil {
			fmt.Println("reached SMB")

			smbpay := app.Payload()

			appNewPayload := make([]byte, len(smbpay))

			buildPayload(appNewPayload)
			// netbios session plus SMB header
			if len(smbpay) > 36 {
				copy(appNewPayload[0:36], smbpay[0:36])
			}
			copy(*packet.ApplicationLayer().(*gopacket.Payload), appNewPayload)

		}

	}
}
