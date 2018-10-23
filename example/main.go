package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"text/tabwriter"

	"github.com/krolaw/dhcp4"
	"github.com/leslie-qiwa/dhcp4client"
)

func dumpPacket(pkt *dhcp4.Packet) {
	w := tabwriter.NewWriter(os.Stdout, 10, 2, 2, ' ', tabwriter.AlignRight)
	defer w.Flush()

	fmt.Fprintf(w, "Message Type:\t %s\n", pkt.OpCode())
	fmt.Fprintf(w, "Hardware Type:\t %d\n", pkt.HType())
	fmt.Fprintf(w, "Hardware Address Length:\t %d\n", pkt.HLen())
	fmt.Fprintf(w, "Hops:\t %d\n", pkt.Hops())
	fmt.Fprintf(w, "Transaction ID:\t 0x%x\n", pkt.XId())
	fmt.Fprintf(w, "Seconds elapsed:\t %d\n", binary.BigEndian.Uint16(pkt.Secs()))
	fmt.Fprintf(w, "Bootp flags:\t %s\n", string(pkt.Flags()))
	fmt.Fprintf(w, "Client IP:\t %s\n", pkt.CIAddr())
	fmt.Fprintf(w, "Your (client) IP:\t %s\n", pkt.YIAddr())
	fmt.Fprintf(w, "Next Server IP:\t %s\n", pkt.SIAddr())
	fmt.Fprintf(w, "Relay Agent IP:\t %s\n", pkt.GIAddr())
	fmt.Fprintf(w, "Client MAC:\t %s\n", pkt.CHAddr())
	fmt.Fprintf(w, "Server host name:\t %s\n", string(pkt.SName()))
	fmt.Fprintf(w, "Boot file name:\t %s\n", string(pkt.File()))
}

func main() {
	//We need to set the connection ports to 1068 and 1067 so we don't need root access
	localPort := flag.Int("lp", 1068, "dhcp client listen port. 1068 as default to avoid requesting root access")
	serverPort := flag.Int("sp", 67, "dhcp server listen port")
	mac := flag.String("mac", "11-22-33-44-55-66", "mac address")

	flag.Parse()

	m, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatal(err)
	}

	if len(flag.Args()) != 1 {
		fmt.Println("example <options> interface")
		flag.PrintDefaults()
		return
	}

	fmt.Printf("local port: %d, server port: %d, mac: %s, nic: %s\n", *localPort, *serverPort, *mac, flag.Args()[0])

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	index := -1
	for i := 0; i < len(interfaces); i++ {
		if interfaces[i].Name == flag.Args()[0] {
			index = interfaces[i].Index
			break
		}
	}
	if index == -1 {
		log.Fatal("interface is not found")
	}

	c, err := dhcp4client.NewPacketSock(index, uint16(*localPort), uint16(*serverPort))
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	exampleClient, err := dhcp4client.New(dhcp4client.HardwareAddr(m), dhcp4client.Connection(c))
	if err != nil {
		log.Fatal(err)
	}
	defer exampleClient.Close()

	discoveryPacket, err := exampleClient.SendDiscoverPacket()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n-------- discovery packet --------")
	dumpPacket(&discoveryPacket)

	offerPacket, err := exampleClient.GetOffer(&discoveryPacket)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n-------- offer packet --------")
	dumpPacket(&offerPacket)

	requestPacket, err := exampleClient.SendRequest(&offerPacket)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n-------- request packet --------")
	dumpPacket(&requestPacket)

	ackPacket, err := exampleClient.GetAcknowledgement(&requestPacket)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n-------- ack packet --------")
	dumpPacket(&ackPacket)
}
