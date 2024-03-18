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
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/hypercube"
	"github.com/np-guard/models/pkg/interval"
	spec "github.com/np-guard/models/pkg/model"
)

type ProtocolStr string

const numDimensions = 5

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP ProtocolStr = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP ProtocolStr = "UDP"
	// ProtocolICMP is the ICMP protocol.
	ProtocolICMP ProtocolStr = "ICMP"
)

const (
	MinICMPtype int64 = 0
	MaxICMPtype int64 = 255
	MinICMPcode int64 = 0
	MaxICMPcode int64 = 254
	minProtocol int64 = TCP
	maxProtocol int64 = ICMP
	MinPort     int64 = 1
	MaxPort     int64 = 65535
)

const (
	// since iota starts with 0, the first value
	// defined here will be the default
	TCP int64 = iota
	UDP
	ICMP
)

const (
	AllConnections = "All Connections"
	NoConnections  = "No Connections"
)

type Dimension int

const (
	protocol Dimension = 0
	srcPort  Dimension = 1
	dstPort  Dimension = 2
	icmpType Dimension = 3
	icmpCode Dimension = 4
)

const propertySeparator string = " "

// dimensionsList is the ordered list of dimensions in the ConnectionSet object
// this should be the only place where the order is hard-coded
var dimensionsList = []Dimension{
	protocol,
	srcPort,
	dstPort,
	icmpType,
	icmpCode,
}

func getDimensionDomain(dim Dimension) *interval.CanonicalSet {
	switch dim {
	case protocol:
		return interval.New(minProtocol, maxProtocol).ToSet()
	case srcPort:
		return interval.New(MinPort, MaxPort).ToSet()
	case dstPort:
		return interval.New(MinPort, MaxPort).ToSet()
	case icmpType:
		return interval.New(MinICMPtype, MaxICMPtype).ToSet()
	case icmpCode:
		return interval.New(MinICMPcode, MaxICMPcode).ToSet()
	}
	return nil
}

func getDimensionDomainsList() []*interval.CanonicalSet {
	res := make([]*interval.CanonicalSet, len(dimensionsList))
	for i := range dimensionsList {
		res[i] = getDimensionDomain(dimensionsList[i])
	}
	return res
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// new connection set dimensions:
// protocol
// src port
// dst port
// icmp type
// icmp code

type ConnectionSet struct {
	AllowAll             bool
	connectionProperties *hypercube.CanonicalSet
	IsStateful           int // default is StatefulUnknown
}

func NewConnectionSet(all bool) *ConnectionSet {
	return &ConnectionSet{AllowAll: all, connectionProperties: hypercube.NewCanonicalSet(numDimensions)}
}

func NewConnectionSetWithCube(cube *hypercube.CanonicalSet) *ConnectionSet {
	res := NewConnectionSet(false)
	res.connectionProperties.Union(cube)
	if res.isAllConnectionsWithoutAllowAll() {
		return NewConnectionSet(true)
	}
	return res
}

func (conn *ConnectionSet) Copy() *ConnectionSet {
	return &ConnectionSet{
		AllowAll:             conn.AllowAll,
		connectionProperties: conn.connectionProperties.Copy(),
		IsStateful:           conn.IsStateful,
	}
}

func (conn *ConnectionSet) Intersection(other *ConnectionSet) *ConnectionSet {
	if other.AllowAll {
		return conn.Copy()
	}
	if conn.AllowAll {
		return other.Copy()
	}
	return &ConnectionSet{AllowAll: false, connectionProperties: conn.connectionProperties.Intersect(other.connectionProperties)}
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

func getAllPropertiesObject() *hypercube.CanonicalSet {
	return hypercube.FromCube(getDimensionDomainsList())
}

func (conn *ConnectionSet) isAllConnectionsWithoutAllowAll() bool {
	if conn.AllowAll {
		return false
	}
	return conn.connectionProperties.Equal(getAllPropertiesObject())
}

// Subtract
// ToDo: Subtract seems to ignore IsStateful (see issue #199):
//  1. is the delta connection stateful
//  2. connectionProperties is identical but conn stateful while other is not
//     the 2nd item can be computed here, with enhancement to relevant structure
//     the 1st can not since we do not know where exactly the statefullness came from
func (conn *ConnectionSet) Subtract(other *ConnectionSet) *ConnectionSet {
	if conn.IsEmpty() || other.IsEmpty() {
		return conn
	}
	if other.AllowAll {
		return NewConnectionSet(false)
	}
	var connProperites *hypercube.CanonicalSet
	if conn.AllowAll {
		connProperites = getAllPropertiesObject()
	} else {
		connProperites = conn.connectionProperties
	}
	return &ConnectionSet{AllowAll: false, connectionProperties: connProperites.Subtract(other.connectionProperties)}
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

// makeCube returns a new hypercube.CanonicalSet created from a single input cube
// the input cube is given as an ordered list of integer values, where each two values
// represent the range (start,end) for a dimension value
func makeCube(values ...int64) *hypercube.CanonicalSet {
	cube := []*interval.CanonicalSet{}
	for i := 0; i < len(values); i += 2 {
		cube = append(cube, interval.New(values[i], values[i+1]).ToSet())
	}
	return hypercube.FromCube(cube)
}

func (conn *ConnectionSet) AddTCPorUDPConn(protocol ProtocolStr, srcMinP, srcMaxP, dstMinP, dstMaxP int64) {
	var cube *hypercube.CanonicalSet
	switch protocol {
	case ProtocolTCP:
		cube = makeCube(TCP, TCP, srcMinP, srcMaxP, dstMinP, dstMaxP, MinICMPtype, MaxICMPtype, MinICMPcode, MaxICMPcode)
	case ProtocolUDP:
		cube = makeCube(UDP, UDP, srcMinP, srcMaxP, dstMinP, dstMaxP, MinICMPtype, MaxICMPtype, MinICMPcode, MaxICMPcode)
	}
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// check if all connections allowed after this union
	if conn.isAllConnectionsWithoutAllowAll() {
		conn.AllowAll = true
		conn.connectionProperties = hypercube.NewCanonicalSet(numDimensions)
	}
}

func (conn *ConnectionSet) AddICMPConnection(icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax int64) {
	cube := makeCube(ICMP, ICMP, MinPort, MaxPort, MinPort, MaxPort, icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax)
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// check if all connections allowed after this union
	if conn.isAllConnectionsWithoutAllowAll() {
		conn.AllowAll = true
		conn.connectionProperties = hypercube.NewCanonicalSet(numDimensions)
	}
}

func (conn *ConnectionSet) Equal(other *ConnectionSet) bool {
	if conn.AllowAll != other.AllowAll {
		return false
	}
	if conn.AllowAll {
		return true
	}
	return conn.connectionProperties.Equal(other.connectionProperties)
}

func getProtocolStr(p int64) string {
	switch p {
	case TCP:
		return string(ProtocolTCP)
	case UDP:
		return string(ProtocolUDP)
	case ICMP:
		return string(ProtocolICMP)
	}
	return ""
}

func getDimensionStr(dimValue *interval.CanonicalSet, dim Dimension) string {
	if dimValue.Equal(getDimensionDomain(dim)) {
		// avoid adding dimension str on full dimension values
		return ""
	}
	switch dim {
	case protocol:
		pList := []string{}
		for p := minProtocol; p <= maxProtocol; p++ {
			if dimValue.Contains(p) {
				pList = append(pList, getProtocolStr(p))
			}
		}
		return "protocol: " + strings.Join(pList, ",")
	case srcPort:
		return "src-ports: " + dimValue.String()
	case dstPort:
		return "dst-ports: " + dimValue.String()
	case icmpType:
		return "icmp-type: " + dimValue.String()
	case icmpCode:
		return "icmp-code: " + dimValue.String()
	}
	return ""
}

func filterEmptyPropertiesStr(inputList []string) []string {
	res := []string{}
	for _, propertyStr := range inputList {
		if propertyStr != "" {
			res = append(res, propertyStr)
		}
	}
	return res
}

func getICMPbasedCubeStr(protocolsValues, icmpTypeValues, icmpCodeValues *interval.CanonicalSet) string {
	strList := []string{
		getDimensionStr(protocolsValues, protocol),
		getDimensionStr(icmpTypeValues, icmpType),
		getDimensionStr(icmpCodeValues, icmpCode),
	}
	return strings.Join(filterEmptyPropertiesStr(strList), propertySeparator)
}

func getPortBasedCubeStr(protocolsValues, srcPortsValues, dstPortsValues *interval.CanonicalSet) string {
	strList := []string{
		getDimensionStr(protocolsValues, protocol),
		getDimensionStr(srcPortsValues, srcPort),
		getDimensionStr(dstPortsValues, dstPort),
	}
	return strings.Join(filterEmptyPropertiesStr(strList), propertySeparator)
}

func getMixedProtocolsCubeStr(protocols *interval.CanonicalSet) string {
	// TODO: make sure other dimension values are full
	return getDimensionStr(protocols, protocol)
}

func getConnsCubeStr(cube []*interval.CanonicalSet) string {
	protocols := cube[protocol]
	if (protocols.Contains(TCP) || protocols.Contains(UDP)) && !protocols.Contains(ICMP) {
		return getPortBasedCubeStr(cube[protocol], cube[srcPort], cube[dstPort])
	}
	if protocols.Contains(ICMP) && !(protocols.Contains(TCP) || protocols.Contains(UDP)) {
		return getICMPbasedCubeStr(cube[protocol], cube[icmpType], cube[icmpCode])
	}
	return getMixedProtocolsCubeStr(protocols)
}

// String returns a string representation of a ConnectionSet object
func (conn *ConnectionSet) String() string {
	if conn.AllowAll {
		return AllConnections
	} else if conn.IsEmpty() {
		return NoConnections
	}
	resStrings := []string{}
	// get cubes and cube str per each cube
	cubes := conn.connectionProperties.GetCubesList()
	for _, cube := range cubes {
		resStrings = append(resStrings, getConnsCubeStr(cube))
	}

	sort.Strings(resStrings)
	return strings.Join(resStrings, "; ")
}

type ConnDetails spec.ProtocolList

func getCubeAsTCPItems(cube []*interval.CanonicalSet, protocol spec.TcpUdpProtocol) []spec.TcpUdp {
	tcpItemsTemp := []spec.TcpUdp{}
	tcpItemsFinal := []spec.TcpUdp{}
	// consider src ports
	srcPorts := cube[srcPort]
	if !srcPorts.Equal(getDimensionDomain(srcPort)) {
		// iterate the interval in the interval-set
		for _, interval := range srcPorts.Intervals() {
			tcpRes := spec.TcpUdp{Protocol: protocol, MinSourcePort: int(interval.Start), MaxSourcePort: int(interval.End)}
			tcpItemsTemp = append(tcpItemsTemp, tcpRes)
		}
	} else {
		tcpItemsTemp = append(tcpItemsTemp, spec.TcpUdp{Protocol: protocol})
	}
	// consider dst ports
	dstPorts := cube[dstPort]
	if !dstPorts.Equal(getDimensionDomain(dstPort)) {
		// iterate the interval in the interval-set
		for _, interval := range dstPorts.Intervals() {
			for _, tcpItemTemp := range tcpItemsTemp {
				tcpRes := spec.TcpUdp{
					Protocol:           protocol,
					MinSourcePort:      tcpItemTemp.MinSourcePort,
					MaxSourcePort:      tcpItemTemp.MaxSourcePort,
					MinDestinationPort: int(interval.Start),
					MaxDestinationPort: int(interval.End),
				}
				tcpItemsFinal = append(tcpItemsFinal, tcpRes)
			}
		}
	} else {
		tcpItemsFinal = tcpItemsTemp
	}
	return tcpItemsFinal
}

func getIntervalNumbers(c *interval.CanonicalSet) []int {
	res := []int{}
	for _, interval := range c.Intervals() {
		for i := interval.Start; i <= interval.End; i++ {
			res = append(res, int(i))
		}
	}
	return res
}

func getCubeAsICMPItems(cube []*interval.CanonicalSet) []spec.Icmp {
	icmpTypes := cube[icmpType]
	icmpCodes := cube[icmpCode]
	if icmpTypes.Equal(getDimensionDomain(icmpType)) && icmpCodes.Equal(getDimensionDomain(icmpCode)) {
		return []spec.Icmp{{Protocol: spec.IcmpProtocolICMP}}
	}
	res := []spec.Icmp{}
	if icmpTypes.Equal(getDimensionDomain(icmpType)) {
		codeNumbers := getIntervalNumbers(icmpCodes)
		for i := range codeNumbers {
			res = append(res, spec.Icmp{Protocol: spec.IcmpProtocolICMP, Code: &codeNumbers[i]})
		}
		return res
	}
	if icmpCodes.Equal(getDimensionDomain(icmpCode)) {
		typeNumbers := getIntervalNumbers(icmpTypes)
		for i := range typeNumbers {
			res = append(res, spec.Icmp{Protocol: spec.IcmpProtocolICMP, Type: &typeNumbers[i]})
		}
		return res
	}
	// iterate both codes and types
	typeNumbers := getIntervalNumbers(icmpTypes)
	codeNumbers := getIntervalNumbers(icmpCodes)
	for i := range typeNumbers {
		for j := range codeNumbers {
			res = append(res, spec.Icmp{Protocol: spec.IcmpProtocolICMP, Type: &typeNumbers[i], Code: &codeNumbers[j]})
		}
	}
	return res
}

func ConnToJSONRep(c *ConnectionSet) ConnDetails {
	if c == nil {
		return nil // one of the connections in connectionDiff can be empty
	}
	if c.AllowAll {
		return ConnDetails(spec.ProtocolList{spec.AnyProtocol{Protocol: spec.AnyProtocolProtocolANY}})
	}
	res := spec.ProtocolList{}

	cubes := c.connectionProperties.GetCubesList()
	for _, cube := range cubes {
		protocols := cube[protocol]
		if protocols.Contains(TCP) {
			tcpItems := getCubeAsTCPItems(cube, spec.TcpUdpProtocolTCP)
			for _, item := range tcpItems {
				res = append(res, item)
			}
		}
		if protocols.Contains(UDP) {
			udpItems := getCubeAsTCPItems(cube, spec.TcpUdpProtocolUDP)
			for _, item := range udpItems {
				res = append(res, item)
			}
		}
		if protocols.Contains(ICMP) {
			icmpItems := getCubeAsICMPItems(cube)
			for _, item := range icmpItems {
				res = append(res, item)
			}
		}
	}

	return ConnDetails(res)
}

// NewTCPConnectionSet returns a ConnectionSet object with TCP protocol (all ports)
func NewTCPConnectionSet() *ConnectionSet {
	res := NewConnectionSet(false)
	res.AddTCPorUDPConn(ProtocolTCP, MinPort, MaxPort, MinPort, MaxPort)
	return res
}

// copyCube returns a new slice of interval copied from input cube
func copyCube(cube []*interval.CanonicalSet) []*interval.CanonicalSet {
	newCube := make([]*interval.CanonicalSet, len(cube))
	for i, intervalSet := range cube {
		newCube[i] = intervalSet.Copy()
	}
	return newCube
}
