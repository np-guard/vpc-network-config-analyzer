// Copyright 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package common

import (
	"fmt"
	"sort"
	"strings"
)

type Protocol string

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP Protocol = "UDP"
	// ProtocolICMP is the ICMP protocol.
	ProtocolICMP Protocol = "ICMP"
)

const (
	numDimensions       = 5
	minICMPtype   int64 = 0
	minICMPcode   int64 = 0
	maxICMPcode   int64 = 254
)

const (
	// since iota starts with 0, the first value
	// defined here will be the default
	TCP int64 = iota
	UDP
	ICMP
)

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// new connection set dimensions:
// protocol
// src port
// dst port
// icmp type
// icmp code

type ConnectionSet struct {
	AllowAll             bool
	connectionProperties *CanonicalHypercubeSet
}

func NewConnectionSet(all bool) *ConnectionSet {
	return &ConnectionSet{AllowAll: all, connectionProperties: NewCanonicalHypercubeSet(5)}
}

func (conn *ConnectionSet) Copy() *ConnectionSet {
	return &ConnectionSet{AllowAll: conn.AllowAll, connectionProperties: conn.connectionProperties.Copy()}
}

func (conn *ConnectionSet) Intersection(other *ConnectionSet) *ConnectionSet {
	if other.AllowAll {
		return conn.Copy()
	}
	if conn.AllowAll {
		return other.Copy()
	}
	return &ConnectionSet{AllowAll: false, connectionProperties: conn.connectionProperties.Intersection(other.connectionProperties)}
}

func (conn *ConnectionSet) IsEmpty() bool {
	if conn.AllowAll {
		return false
	}
	return conn.connectionProperties.IsEmpty()
}

func (conn *ConnectionSet) Union(other *ConnectionSet) *ConnectionSet {
	if conn.AllowAll || other.AllowAll {
		return NewConnectionSet(true)
	}
	if other.IsEmpty() {
		return conn.Copy()
	}
	if conn.IsEmpty() {
		return other.Copy()
	}
	res := &ConnectionSet{AllowAll: false, connectionProperties: conn.connectionProperties.Union(other.connectionProperties)}
	if res.isAllConnectionsWithoutAllowAll() {
		return NewConnectionSet(true)
	}
	return res
}

func getAllPropertiesObject() *CanonicalHypercubeSet {
	//res := NewCanonicalHypercubeSet(numDimensions)
	// TODO avoid hard-coded order of dimensions and intervals
	res := CreateFromCubeShort(TCP, ICMP, MinPort, MaxPort, MinPort, MaxPort, minICMPtype, MaxICMPtype, minICMPcode, maxICMPcode)
	return res
}

func (conn *ConnectionSet) isAllConnectionsWithoutAllowAll() bool {
	if conn.AllowAll {
		return false
	}
	return conn.connectionProperties.Equals(getAllPropertiesObject())

}

func (conn *ConnectionSet) Subtract(other *ConnectionSet) *ConnectionSet {
	if conn.IsEmpty() || other.IsEmpty() {
		return conn
	}
	if other.AllowAll {
		return NewConnectionSet(false)
	}
	var connProperites *CanonicalHypercubeSet
	if conn.AllowAll {
		connProperites = getAllPropertiesObject()
	} else {
		connProperites = conn.connectionProperties
	}
	return &ConnectionSet{AllowAll: false, connectionProperties: connProperites.Subtraction(other.connectionProperties)}
}

func (conn *ConnectionSet) ContainedIn(other *ConnectionSet) (bool, error) {
	if other.AllowAll {
		return true, nil
	}
	if conn.AllowAll {
		return false, nil
	}
	res, err := conn.connectionProperties.ContainedIn(other.connectionProperties)
	return res, err
}

func (conn *ConnectionSet) AddTCPorUDPConn(protocol Protocol, srcMinP, srcMaxP, dstMinP, dstMaxP int64) {
	var cube *CanonicalHypercubeSet
	switch protocol {
	case ProtocolTCP:
		cube = CreateFromCubeShort(TCP, TCP, srcMinP, srcMaxP, dstMinP, dstMaxP, minICMPtype, MaxICMPtype, minICMPcode, maxICMPcode)
	case ProtocolUDP:
		cube = CreateFromCubeShort(UDP, UDP, srcMinP, srcMaxP, dstMinP, dstMaxP, minICMPtype, MaxICMPtype, minICMPcode, maxICMPcode)
		/*case ProtocolICMP:
		cube = CreateFromCubeShort(ICMP, ICMP, minPort, maxPort, minPort, maxPort, minP, maxP, minICMPcode, maxICMPcode)*/
	}
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// TODO: check if all connections allowed after this union
}

func (conn *ConnectionSet) AddICMPConnection(icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax int64) {
	cube := CreateFromCubeShort(ICMP, ICMP, MinPort, MaxPort, MinPort, MaxPort, icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax)
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// TODO: check if all connections allowed after this union
}

/*func (conn *ConnectionSet) AddConnection(protocol Protocol, minP, maxP int64) {
	var cube *CanonicalHypercubeSet
	switch protocol {
	case ProtocolTCP:
		cube = CreateFromCubeShort(TCP, TCP, MinPort, MaxPort, minP, maxP, minICMPtype, MaxICMPtype, minICMPcode, maxICMPcode)
	case ProtocolUDP:
		cube = CreateFromCubeShort(UDP, UDP, MinPort, MaxPort, minP, maxP, minICMPtype, MaxICMPtype, minICMPcode, maxICMPcode)
	case ProtocolICMP:
		cube = CreateFromCubeShort(ICMP, ICMP, MinPort, MaxPort, MinPort, MaxPort, minP, maxP, minICMPcode, maxICMPcode)
	}
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// TODO: check if all connections allowed after this union
}*/

func (conn *ConnectionSet) Equal(other *ConnectionSet) bool {
	if conn.AllowAll != other.AllowAll {
		return false
	}
	if conn.AllowAll {
		return true
	}
	return conn.connectionProperties.Equals(other.connectionProperties)
}

func (conn *ConnectionSet) String() string {
	if conn.AllowAll {
		return "All Connections"
	} else if conn.IsEmpty() {
		return "No Connections"
	}
	resStrings := []string{}
	// get cubes and cube str per each cube
	/*for protocol, ports := range conn.AllowedProtocols {
		resStrings = append(resStrings, string(protocol)+" "+ports.String())
	}*/
	cubes := conn.connectionProperties.GetCubesList()
	for _, cube := range cubes {
		// TODO: avoid hard-coded order of dimensions
		protocols := cube[0]
		srcPorts := cube[1]
		dstPorts := cube[2]
		icmpType := cube[3]
		icmpCode := cube[4]
		resProtocols := []string{}
		if protocols.Contains(ICMP) {
			resProtocols = append(resProtocols, "ICMP")
		}
		if protocols.Contains(TCP) {
			resProtocols = append(resProtocols, "TCP")
		}
		if protocols.Contains(UDP) {
			resProtocols = append(resProtocols, "UDP")
		}
		if protocols.Contains(ICMP) && (protocols.Contains(TCP) || protocols.Contains(UDP)) {
			//TODO: check that the other properties are "all"
			res := strings.Join(resProtocols, ",")
			resStrings = append(resStrings, res)
		} else if protocols.Contains(TCP) || protocols.Contains(UDP) {
			res := strings.Join(resProtocols, ",")
			allPorts := NewPortSetAllPorts()
			if !srcPorts.Equal(allPorts.Ports) {
				res += fmt.Sprintf(" src-ports: %s", srcPorts.String())
			}
			if !dstPorts.Equal(allPorts.Ports) {
				res += fmt.Sprintf(" dst-ports: %s", dstPorts.String())
			}
			resStrings = append(resStrings, res)
		} else if protocols.Contains(ICMP) {
			res := strings.Join(resProtocols, ",")
			allTypes := NewICMPAllTypesTemp()
			allCodes := NewICMPAllCodesTemp()
			if !icmpType.Equal(allTypes.Ports) {
				res += fmt.Sprintf(" icmp-type: %s", icmpType.String())
			}
			if !icmpCode.Equal(allCodes.Ports) {
				res += fmt.Sprintf(" icmp-code: %s", icmpCode.String())
			}
			resStrings = append(resStrings, res)
		}
	}

	sort.Strings(resStrings)
	return strings.Join(resStrings, ",")
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
// ConnectionSet represents a set of allowed connections between two peers on a k8s env
type ConnectionSet struct {
	AllowAll bool
	//TODO: handle ICMP type & code. currently using PortSet to represent ICMP type interval only
	AllowedProtocols map[Protocol]*PortSet // map from protocol name to set of allowed ports
}

// MakeConnectionSet returns a ConnectionSet object with all connections or no connections
func MakeConnectionSet(all bool) ConnectionSet {
	if all {
		return ConnectionSet{AllowAll: true, AllowedProtocols: map[Protocol]*PortSet{}}
	}
	return ConnectionSet{AllowedProtocols: map[Protocol]*PortSet{}}
}

func (conn *ConnectionSet) Copy() *ConnectionSet {
	res := &ConnectionSet{}
	res.AllowAll = conn.AllowAll
	res.AllowedProtocols = make(map[Protocol]*PortSet, len(conn.AllowedProtocols))
	for protocol, ports := range conn.AllowedProtocols {
		portsCopy := ports.Copy()
		res.AllowedProtocols[protocol] = &portsCopy
	}
	return res
}

// Intersection updates ConnectionSet object to be the intersection result with other ConnectionSet
func (conn *ConnectionSet) Intersection(other ConnectionSet) {
	if other.AllowAll {
		return
	}
	if conn.AllowAll {
		conn.AllowAll = false
		for protocol, ports := range other.AllowedProtocols {
			portsCopy := ports.Copy()
			conn.AllowedProtocols[protocol] = &portsCopy
		}
		return
	}
	for protocol := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			delete(conn.AllowedProtocols, protocol)
		} else {
			conn.AllowedProtocols[protocol].Intersection(*otherPorts)
			if conn.AllowedProtocols[protocol].IsEmpty() {
				delete(conn.AllowedProtocols, protocol)
			}
		}
	}
}

// IsEmpty returns true if the ConnectionSet has no allowed connections
func (conn *ConnectionSet) IsEmpty() bool {
	return !conn.AllowAll && len(conn.AllowedProtocols) == 0
}

func (conn *ConnectionSet) isAllConnectionsWithoutAllowAll() bool {
	if conn.AllowAll {
		return false
	}
	allProtocols := []Protocol{ProtocolTCP, ProtocolUDP, ProtocolSCTP, ProtocolICMP}
	for _, protocol := range allProtocols {
		ports, ok := conn.AllowedProtocols[protocol]
		if !ok {
			return false
		} else if !ports.IsAll() {
			return false
		}
	}

	return true
}

func (conn *ConnectionSet) checkIfAllConnections() {
	if conn.isAllConnectionsWithoutAllowAll() {
		conn.AllowAll = true
		conn.AllowedProtocols = map[Protocol]*PortSet{}
	}
}

// Union updates ConnectionSet object to be the union result with other ConnectionSet
func (conn *ConnectionSet) Union(other ConnectionSet) {
	if conn.AllowAll || other.IsEmpty() {
		return
	}
	if other.AllowAll {
		conn.AllowAll = true
		conn.AllowedProtocols = map[Protocol]*PortSet{}
		return
	}
	for protocol := range conn.AllowedProtocols {
		if otherPorts, ok := other.AllowedProtocols[protocol]; ok {
			conn.AllowedProtocols[protocol].Union(*otherPorts)
		}
	}
	for protocol := range other.AllowedProtocols {
		if _, ok := conn.AllowedProtocols[protocol]; !ok {
			portsCopy := other.AllowedProtocols[protocol].Copy()
			conn.AllowedProtocols[protocol] = &portsCopy
		}
	}
	conn.checkIfAllConnections()
}

func (conn *ConnectionSet) Subtract(other ConnectionSet) {
	if conn.IsEmpty() || other.IsEmpty() {
		return
	}
	if other.AllowAll {
		conn.AllowAll = false
		conn.AllowedProtocols = make(map[Protocol]*PortSet, 0)
		return
	}

	if conn.AllowAll {
		conn.AllowAll = false
		conn.AllowedProtocols[ProtocolTCP] = NewPortSetAllPorts()
		conn.AllowedProtocols[ProtocolUDP] = NewPortSetAllPorts()
		conn.AllowedProtocols[ProtocolSCTP] = NewPortSetAllPorts()
		conn.AllowedProtocols[ProtocolICMP] = NewICMPAllTypesTemp()
	}
	for protocol := range conn.AllowedProtocols {
		if otherPorts, ok := other.AllowedProtocols[protocol]; ok {
			conn.AllowedProtocols[protocol].Ports.Subtraction(otherPorts.Ports)
			if conn.AllowedProtocols[protocol].Ports.IsEmpty() {
				delete(conn.AllowedProtocols, protocol)
			}
		}
	}
}

// Contains returns true if the input port+protocol is an allowed connection
func (conn *ConnectionSet) Contains(port, protocol string) bool {
	intPort, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if conn.AllowAll {
		return true
	}
	for allowedProtocol, allowedPorts := range conn.AllowedProtocols {
		if strings.EqualFold(protocol, string(allowedProtocol)) {
			return allowedPorts.Contains(int64(intPort))
		}
	}
	return false
}

// ContainedIn returns true if current ConnectionSet is conatained in the input ConnectionSet object
func (conn *ConnectionSet) ContainedIn(other ConnectionSet) bool {
	if other.AllowAll {
		return true
	}
	if conn.AllowAll {
		return false
	}
	for protocol, ports := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			return false
		}
		if !ports.ContainedIn(*otherPorts) {
			return false
		}
	}
	return true
}

// AddConnection updates current ConnectionSet object with new allowed connection
func (conn *ConnectionSet) AddConnection(protocol Protocol, ports PortSet) {
	if ports.IsEmpty() {
		return
	}
	connPorts, ok := conn.AllowedProtocols[protocol]
	if ok {
		connPorts.Union(ports)
	} else {
		conn.AllowedProtocols[protocol] = &ports
	}
}

// String returns a string representation of the ConnectionSet object
func (conn *ConnectionSet) String() string {
	if conn.AllowAll {
		return "All Connections"
	} else if conn.IsEmpty() {
		return "No Connections"
	}
	resStrings := []string{}
	for protocol, ports := range conn.AllowedProtocols {
		resStrings = append(resStrings, string(protocol)+" "+ports.String())
	}
	sort.Strings(resStrings)
	return strings.Join(resStrings, ",")
}

// Equal returns true if the current ConnectionSet object is equal to the input object
func (conn *ConnectionSet) Equal(other ConnectionSet) bool {
	if conn.AllowAll != other.AllowAll {
		return false
	}
	if len(conn.AllowedProtocols) != len(other.AllowedProtocols) {
		return false
	}
	for protocol, ports := range conn.AllowedProtocols {
		otherPorts, ok := other.AllowedProtocols[protocol]
		if !ok {
			return false
		}
		if !ports.Equal(*otherPorts) {
			return false
		}
	}
	return true
}

// portRange implements the eval.PortRange interface
type portRange struct {
	start int64
	end   int64
}

func (p *portRange) Start() int64 {
	return p.start
}

func (p *portRange) End() int64 {
	return p.end
}

func (p *portRange) String() string {
	if p.End() != p.Start() {
		return fmt.Sprintf("%d-%d", p.Start(), p.End())
	}
	return fmt.Sprintf("%d", p.Start())
}

// ProtocolsAndPortsMap() returns a map from allowed protocol to list of allowed ports ranges.
func (conn *ConnectionSet) ProtocolsAndPortsMap() map[Protocol][]*portRange {
	res := map[Protocol][]*portRange{}
	for protocol, portSet := range conn.AllowedProtocols {
		res[protocol] = []*portRange{}
		// TODO: consider leave the slice of ports empty if portSet covers the full range
		for i := range portSet.Ports.IntervalSet {
			startPort := portSet.Ports.IntervalSet[i].Start
			endPort := portSet.Ports.IntervalSet[i].End
			portRange := &portRange{start: startPort, end: endPort}
			res[protocol] = append(res[protocol], portRange)
		}
	}
	return res
}
*/
