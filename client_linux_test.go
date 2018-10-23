package dhcp4client

import (
	"log"
	"net"
	"syscall"
	"testing"

	"github.com/krolaw/dhcp4"
)

//Example Client
func Test_ExampleLinuxClient(test *testing.T) {
	var err error

	m, err := net.ParseMAC("08-00-27-00-A8-E8")
	if err != nil {
		log.Printf("MAC Error:%v\n", err)
	}

	//Create a connection to use
	c, err := NewPacketSock(2, DefaultSrcPort, DefaultDstPort)
	if err != nil {
		test.Error("Client Connection Generation:" + err.Error())
	}
	defer c.Close()

	exampleClient, err := New(HardwareAddr(m), Connection(c))
	if err != nil {
		test.Fatalf("Error:%v\n", err)
	}
	defer exampleClient.Close()

	success := false

	discoveryPacket, err := exampleClient.SendDiscoverPacket()
	test.Logf("Discovery:%v\n", discoveryPacket)

	if err != nil {
		sc, ok := err.(syscall.Errno)
		if ok {
			//Don't report a network down
			if sc != syscall.ENETDOWN {
				test.Fatalf("Discovery Error:%v\n", err)
			}
		} else {
			test.Fatalf("Discovery Error:%v\n", err)
		}

	}

	offerPacket, err := exampleClient.GetOffer(&discoveryPacket)
	if err != nil {
		test.Fatalf("Offer Error:%v\n", err)
	}

	requestPacket, err := exampleClient.SendRequest(&offerPacket)
	if err != nil {
		test.Fatalf("Send Offer Error:%v\n", err)
	}

	acknowledgementpacket, err := exampleClient.GetAcknowledgement(&requestPacket)
	if err != nil {
		test.Fatalf("Get Ack Error:%v\n", err)
	}

	acknowledgementOptions := acknowledgementpacket.ParseOptions()
	if dhcp4.MessageType(acknowledgementOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.ACK {
		test.Fatalf("Not Acknoledged")
	} else {
		success = true
	}

	test.Logf("Packet:%v\n", acknowledgementpacket)

	if err != nil {
		networkError, ok := err.(net.Error)
		if ok && networkError.Timeout() {
			test.Log("Test Skipping as it didn't find a DHCP Server")
			test.SkipNow()
		}
		test.Fatalf("Error:%v\n", err)
	}

	if !success {
		test.Error("We didn't sucessfully get a DHCP Lease?")
	} else {
		log.Printf("IP Received:%v\n", acknowledgementpacket.YIAddr().String())
	}

}
