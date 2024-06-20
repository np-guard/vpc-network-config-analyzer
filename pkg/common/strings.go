/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ds"
	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
)

const (
	AllConnections = "All Connections"
	NoConnections  = "No Connections"
)
const (
	spaceString    = " "
	protocolString = "protocol: "
	// commaString     = ", "
	semicolonString = "; "
)

func tcpudpProtocolString(p *netset.ProtocolSet, shortVersion bool) string {
	var str string
	switch {
	case p.Size() == 2:
		str = string(netp.ProtocolStringTCP + "," + netp.ProtocolStringUDP)
	case p.Contains(netset.TCPCode):
		str = string(netp.ProtocolStringTCP)
	case p.Contains(netset.UDPCode):
		str = string(netp.ProtocolStringUDP)
	default:
		return ""
	}
	if shortVersion {
		return str
	}
	return protocolString + str
}

func getTCPUDPCubeStr(cube ds.Triple[*netset.ProtocolSet, *netset.PortSet, *netset.PortSet], shortVersion bool) string {
	var ports []string
	if !cube.S2.Equal(netset.AllPorts()) {
		ports = append(ports, "src-ports: "+cube.S2.String())
	}
	if !cube.S3.Equal(netset.AllPorts()) {
		ports = append(ports, "dst-ports: "+cube.S3.String())
	}
	res := tcpudpProtocolString(cube.S1, shortVersion)
	if len(ports) > 0 {
		res += spaceString
	}
	return res + strings.Join(ports, spaceString)
}

func getICMPCubeStr(cube netp.ICMP) string {
	tc := cube.ICMPTypeCode()
	if tc == nil {
		return ""
	}
	if tc.Code == nil {
		if netp.HasSingleCode(tc.Type) {
			return fmt.Sprintf("icmp-type: %d icmp-code: 0", tc.Type)
		}
		return fmt.Sprintf("icmp-type: %d", tc.Type)
	}
	return fmt.Sprintf("icmp-type: %d icmp-code: %d", tc.Type, *tc.Code)
}

// tCPUDPString returns a string representation of a TransportSet object
func tCPUDPString(c *netset.TCPUDPSet, shortVersion bool) string {
	cubes := c.Partitions()
	var resStrings = make([]string, len(cubes))
	for i, cube := range cubes {
		resStrings[i] = getTCPUDPCubeStr(cube, shortVersion)
	}
	sort.Strings(resStrings)
	return strings.Join(resStrings, semicolonString)
}

// iCMPString returns a string representation of an ICMPSet object
func iCMPString(c *netset.ICMPSet, shortVersion bool) string {
	if c.IsEmpty() {
		return ""
	}
	cubes := c.Partitions()
	var resStrings = make([]string, len(cubes))
	for i, cube := range cubes {
		resStrings[i] = getICMPCubeStr(cube)
	}
	sort.Strings(resStrings)
	str := "ICMP"
	if !shortVersion {
		str = protocolString + str
	}
	last := strings.Join(resStrings, semicolonString)
	if last != "" {
		str += spaceString + last
	}
	return str
}

func Stringify(c *connection.Set, shortVersion bool) string {
	if c.IsEmpty() {
		return NoConnections
	} else if c.IsAll() {
		return AllConnections
	}
	tcpString := tCPUDPString(c.TCPUDPSet(), shortVersion)
	icmpString := iCMPString(c.ICMPSet(), shortVersion)

	// Special case: ICMP,UDP or ICMP,TCP
	if strings.HasSuffix(tcpString, string(netp.ProtocolStringTCP)) || strings.HasSuffix(tcpString, string(netp.ProtocolStringUDP)) {
		if strings.HasSuffix(icmpString, string(netp.ProtocolStringICMP)) {
			return fmt.Sprintf("%s,%s", icmpString, tCPUDPString(c.TCPUDPSet(), true))
		}
	}
	if tcpString != "" && icmpString != "" {
		return fmt.Sprintf("%s%s%s", icmpString, semicolonString, tcpString)
	}
	return icmpString + tcpString
}

func ShortString(connections *connection.Set) string {
	return Stringify(connections, true)
}

func LongString(connections *connection.Set) string {
	return Stringify(connections, false)
}
