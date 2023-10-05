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
package connection

import (
	"sort"
	"strings"

	hypercube "github.com/np-guard/vpc-network-config-analyzer/internal/hypercube"
	interval "github.com/np-guard/vpc-network-config-analyzer/internal/interval"
	model "github.com/np-guard/vpc-network-config-analyzer/pkg/common"
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

// IsAllConnections returns whether the input connection string represents all connection (true) or not (false)
func IsAllConnections(conn string) bool { return strings.Contains(conn, AllConnections) }

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

func getDimensionDomain(dim Dimension) *interval.CanonicalIntervalSet {
	switch dim {
	case protocol:
		return interval.CreateFromInterval(minProtocol, maxProtocol)
	case srcPort:
		return interval.CreateFromInterval(MinPort, MaxPort)
	case dstPort:
		return interval.CreateFromInterval(MinPort, MaxPort)
	case icmpType:
		return interval.CreateFromInterval(MinICMPtype, MaxICMPtype)
	case icmpCode:
		return interval.CreateFromInterval(MinICMPcode, MaxICMPcode)
	}
	return nil
}

func getDimensionDomainsList() []*interval.CanonicalIntervalSet {
	res := make([]*interval.CanonicalIntervalSet, len(dimensionsList))
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

const (
	StatefulUnknown int = iota
	StatefulTrue
	StatefulFalse
)

type ConnectionSet struct {
	AllowAll             bool
	connectionProperties *hypercube.CanonicalHypercubeSet
	IsStateful           int // default is StatefulUnknown
}

func NewConnectionSet(all bool) *ConnectionSet {
	return &ConnectionSet{AllowAll: all, connectionProperties: hypercube.NewCanonicalHypercubeSet(numDimensions)}
}

func NewConnectionSetWithStateful(all bool, isStateful int) *ConnectionSet {
	return &ConnectionSet{AllowAll: all, connectionProperties: hypercube.NewCanonicalHypercubeSet(numDimensions), IsStateful: isStateful}
}

func NewConnectionSetWithCube(cube *hypercube.CanonicalHypercubeSet) *ConnectionSet {
	res := NewConnectionSet(false)
	res.connectionProperties.Union(cube)
	if res.isAllConnectionsWithoutAllowAll() {
		return NewConnectionSet(true)
	}
	return res
}

func AllConns() *ConnectionSet {
	return NewConnectionSet(true)
}

func NoConns() *ConnectionSet {
	return NewConnectionSet(false)
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

func getAllPropertiesObject() *hypercube.CanonicalHypercubeSet {
	return hypercube.CreateFromCube(getDimensionDomainsList())
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
	var connProperites *hypercube.CanonicalHypercubeSet
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

func (conn *ConnectionSet) AddTCPorUDPConn(protocol ProtocolStr, srcMinP, srcMaxP, dstMinP, dstMaxP int64) {
	var cube *hypercube.CanonicalHypercubeSet
	switch protocol {
	case ProtocolTCP:
		cube = hypercube.CreateFromCubeShort(TCP, TCP, srcMinP, srcMaxP, dstMinP, dstMaxP, MinICMPtype, MaxICMPtype, MinICMPcode, MaxICMPcode)
	case ProtocolUDP:
		cube = hypercube.CreateFromCubeShort(UDP, UDP, srcMinP, srcMaxP, dstMinP, dstMaxP, MinICMPtype, MaxICMPtype, MinICMPcode, MaxICMPcode)
	}
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// check if all connections allowed after this union
	if conn.isAllConnectionsWithoutAllowAll() {
		conn.AllowAll = true
		conn.connectionProperties = hypercube.NewCanonicalHypercubeSet(numDimensions)
	}
}

func (conn *ConnectionSet) AddICMPConnection(icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax int64) {
	cube := hypercube.CreateFromCubeShort(ICMP, ICMP, MinPort, MaxPort, MinPort, MaxPort, icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax)
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// check if all connections allowed after this union
	if conn.isAllConnectionsWithoutAllowAll() {
		conn.AllowAll = true
		conn.connectionProperties = hypercube.NewCanonicalHypercubeSet(numDimensions)
	}
}

func (conn *ConnectionSet) Equal(other *ConnectionSet) bool {
	if conn.AllowAll != other.AllowAll {
		return false
	}
	if conn.AllowAll {
		return true
	}
	return conn.connectionProperties.Equals(other.connectionProperties)
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

func getDimensionStr(dimValue *interval.CanonicalIntervalSet, dim Dimension) string {
	domainValues := getDimensionDomain(dim)
	if dimValue.Equal(*domainValues) {
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

func getICMPbasedCubeStr(protocolsValues, icmpTypeValues, icmpCodeValues *interval.CanonicalIntervalSet) string {
	strList := []string{
		getDimensionStr(protocolsValues, protocol),
		getDimensionStr(icmpTypeValues, icmpType),
		getDimensionStr(icmpCodeValues, icmpCode),
	}
	return strings.Join(filterEmptyPropertiesStr(strList), propertySeparator)
}

func getPortBasedCubeStr(protocolsValues, srcPortsValues, dstPortsValues *interval.CanonicalIntervalSet) string {
	strList := []string{
		getDimensionStr(protocolsValues, protocol),
		getDimensionStr(srcPortsValues, srcPort),
		getDimensionStr(dstPortsValues, dstPort),
	}
	return strings.Join(filterEmptyPropertiesStr(strList), propertySeparator)
}

func getMixedProtocolsCubeStr(protocols *interval.CanonicalIntervalSet) string {
	// TODO: make sure other dimension values are full
	return getDimensionStr(protocols, protocol)
}

func getConnsCubeStr(cube []*interval.CanonicalIntervalSet) string {
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

type ConnDetails model.ProtocolList

func getCubeAsTCPItems(cube []*interval.CanonicalIntervalSet, protocol model.TcpUdpProtocol) []model.TcpUdp {
	tcpItemsTemp := []model.TcpUdp{}
	tcpItemsFinal := []model.TcpUdp{}
	// consider src ports
	srcPorts := cube[srcPort]
	if !srcPorts.Equal(*getDimensionDomain(srcPort)) {
		// iterate the intervals in the interval-set
		for _, ipInterval := range srcPorts.IntervalSet {
			tcpRes := model.TcpUdp{Protocol: protocol, MinSourcePort: int(ipInterval.Start), MaxSourcePort: int(ipInterval.End)}
			tcpItemsTemp = append(tcpItemsTemp, tcpRes)
		}
	} else {
		tcpItemsTemp = append(tcpItemsTemp, model.TcpUdp{Protocol: protocol})
	}
	// consider dst ports
	dstPorts := cube[dstPort]
	if !dstPorts.Equal(*getDimensionDomain(dstPort)) {
		// iterate the intervals in the interval-set
		for _, ipInterval := range dstPorts.IntervalSet {
			for _, tcpItemTemp := range tcpItemsTemp {
				tcpRes := model.TcpUdp{
					Protocol:           protocol,
					MinSourcePort:      tcpItemTemp.MinSourcePort,
					MaxSourcePort:      tcpItemTemp.MaxSourcePort,
					MinDestinationPort: int(ipInterval.Start),
					MaxDestinationPort: int(ipInterval.End),
				}
				tcpItemsFinal = append(tcpItemsFinal, tcpRes)
			}
		}
	} else {
		tcpItemsFinal = tcpItemsTemp
	}
	return tcpItemsFinal
}

func getIntervalNumbers(c *interval.CanonicalIntervalSet) []int {
	res := []int{}
	for _, ipInterval := range c.IntervalSet {
		for i := ipInterval.Start; i <= ipInterval.End; i++ {
			res = append(res, int(i))
		}
	}
	return res
}

func getCubeAsICMPItems(cube []*interval.CanonicalIntervalSet) []model.Icmp {
	icmpTypes := cube[icmpType]
	icmpCodes := cube[icmpCode]
	if icmpTypes.Equal(*getDimensionDomain(icmpType)) && icmpCodes.Equal(*getDimensionDomain(icmpCode)) {
		return []model.Icmp{{Protocol: model.IcmpProtocolICMP}}
	}
	res := []model.Icmp{}
	if icmpTypes.Equal(*getDimensionDomain(icmpType)) {
		codeNumbers := getIntervalNumbers(icmpCodes)
		for i := range codeNumbers {
			res = append(res, model.Icmp{Protocol: model.IcmpProtocolICMP, Code: &codeNumbers[i]})
		}
		return res
	}
	if icmpCodes.Equal(*getDimensionDomain(icmpCode)) {
		typeNumbers := getIntervalNumbers(icmpTypes)
		for i := range typeNumbers {
			res = append(res, model.Icmp{Protocol: model.IcmpProtocolICMP, Type: &typeNumbers[i]})
		}
		return res
	}
	// iterate both codes and types
	typeNumbers := getIntervalNumbers(icmpTypes)
	codeNumbers := getIntervalNumbers(icmpCodes)
	for i := range typeNumbers {
		for j := range codeNumbers {
			res = append(res, model.Icmp{Protocol: model.IcmpProtocolICMP, Type: &typeNumbers[i], Code: &codeNumbers[j]})
		}
	}
	return res
}

func ConnToJSONRep(c *ConnectionSet) ConnDetails {
	if c.AllowAll {
		return ConnDetails(model.ProtocolList{model.AnyProtocol{Protocol: model.AnyProtocolProtocolANY}})
	}
	res := model.ProtocolList{}

	cubes := c.connectionProperties.GetCubesList()
	for _, cube := range cubes {
		protocols := cube[protocol]
		if protocols.Contains(TCP) {
			tcpItems := getCubeAsTCPItems(cube, model.TcpUdpProtocolTCP)
			for _, item := range tcpItems {
				res = append(res, item)
			}
		}
		if protocols.Contains(UDP) {
			udpItems := getCubeAsTCPItems(cube, model.TcpUdpProtocolUDP)
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

// EnhancedString returns a connection string with possibly added asterisk for unidirectional connection,
// and bool result indicating if such asterisk was added
func (conn *ConnectionSet) EnhancedString() string {
	if conn.IsStateful == StatefulFalse {
		return conn.String() + " *"
	}
	return conn.String()
}

// NewTCPConnectionSet returns a ConnectionSet object with TCP protocol (all ports)
func NewTCPConnectionSet() *ConnectionSet {
	res := NewConnectionSet(false)
	res.AddTCPorUDPConn(ProtocolTCP, MinPort, MaxPort, MinPort, MaxPort)
	return res
}

// copyCube returns a new slice of intervals copied from input cube
func copyCube(cube []*interval.CanonicalIntervalSet) []*interval.CanonicalIntervalSet {
	newCube := make([]*interval.CanonicalIntervalSet, len(cube))
	for i, ipInterval := range cube {
		newInterval := ipInterval.Copy()
		newCube[i] = &newInterval
	}
	return newCube
}

// ResponseConnection returns a new ConnectionSet object, built from the input ConnectionSet object,
// which is the response's should be connection.
// For TCP and UDP the src and dst ports on relevant cubes are being switched,
// and for ICMP (which does not have src or dst ports) the connection is copied on relevant cubes
func (conn *ConnectionSet) ResponseConnection() *ConnectionSet {
	if conn.AllowAll || conn.IsEmpty() {
		return conn
	}
	res := NewConnectionSet(false)
	cubes := conn.connectionProperties.GetCubesList()

	for _, cube := range cubes {
		protocols := cube[protocol]
		if protocols.Contains(TCP) || protocols.Contains(UDP) {
			srcPorts := cube[srcPort]
			dstPorts := cube[dstPort]
			// if the entire domain is enabled by both src and dst no need to switch
			if !srcPorts.Equal(*getDimensionDomain(srcPort)) || !dstPorts.Equal(*getDimensionDomain(dstPort)) {
				newCube := copyCube(cube)
				newCube[srcPort], newCube[dstPort] = newCube[dstPort], newCube[srcPort]
				res.connectionProperties = res.connectionProperties.Union(hypercube.CreateFromCube(newCube))
			} else {
				res.connectionProperties = res.connectionProperties.Union(hypercube.CreateFromCube(cube))
			}
		} else if protocols.Contains(ICMP) {
			res.connectionProperties = res.connectionProperties.Union(hypercube.CreateFromCube(cube))
		}
	}
	return res
}
