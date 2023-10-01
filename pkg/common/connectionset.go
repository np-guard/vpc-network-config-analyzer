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

func getDimensionDomain(dim Dimension) *CanonicalIntervalSet {
	switch dim {
	case protocol:
		return CreateFromInterval(minProtocol, maxProtocol)
	case srcPort:
		return CreateFromInterval(MinPort, MaxPort)
	case dstPort:
		return CreateFromInterval(MinPort, MaxPort)
	case icmpType:
		return CreateFromInterval(MinICMPtype, MaxICMPtype)
	case icmpCode:
		return CreateFromInterval(MinICMPcode, MaxICMPcode)
	}
	return nil
}

func getDimensionDomainsList() []*CanonicalIntervalSet {
	res := make([]*CanonicalIntervalSet, len(dimensionsList))
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
	connectionProperties *CanonicalHypercubeSet
	IsStateful           int // default is StatefulUnknown
}

func NewConnectionSet(all bool) *ConnectionSet {
	return &ConnectionSet{AllowAll: all, connectionProperties: NewCanonicalHypercubeSet(numDimensions)}
}

func NewConnectionSetWithStateful(all bool, isStateful int) *ConnectionSet {
	return &ConnectionSet{AllowAll: all, connectionProperties: NewCanonicalHypercubeSet(numDimensions), IsStateful: isStateful}
}

func NewConnectionSetWithCube(cube *CanonicalHypercubeSet) *ConnectionSet {
	res := NewConnectionSet(false)
	res.connectionProperties.Union(cube)
	if res.isAllConnectionsWithoutAllowAll() {
		return NewConnectionSet(true)
	}
	return res
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
	return CreateFromCube(getDimensionDomainsList())
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

func (conn *ConnectionSet) AddTCPorUDPConn(protocol ProtocolStr, srcMinP, srcMaxP, dstMinP, dstMaxP int64) {
	var cube *CanonicalHypercubeSet
	switch protocol {
	case ProtocolTCP:
		cube = CreateFromCubeShort(TCP, TCP, srcMinP, srcMaxP, dstMinP, dstMaxP, MinICMPtype, MaxICMPtype, MinICMPcode, MaxICMPcode)
	case ProtocolUDP:
		cube = CreateFromCubeShort(UDP, UDP, srcMinP, srcMaxP, dstMinP, dstMaxP, MinICMPtype, MaxICMPtype, MinICMPcode, MaxICMPcode)
	}
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// check if all connections allowed after this union
	if conn.isAllConnectionsWithoutAllowAll() {
		conn.AllowAll = true
		conn.connectionProperties = NewCanonicalHypercubeSet(numDimensions)
	}
}

func (conn *ConnectionSet) AddICMPConnection(icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax int64) {
	cube := CreateFromCubeShort(ICMP, ICMP, MinPort, MaxPort, MinPort, MaxPort, icmpTypeMin, icmpTypeMax, icmpCodeMin, icmpCodeMax)
	conn.connectionProperties = conn.connectionProperties.Union(cube)
	// check if all connections allowed after this union
	if conn.isAllConnectionsWithoutAllowAll() {
		conn.AllowAll = true
		conn.connectionProperties = NewCanonicalHypercubeSet(numDimensions)
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

func getDimensionStr(dimValue *CanonicalIntervalSet, dim Dimension) string {
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

func getICMPbasedCubeStr(protocolsValues, icmpTypeValues, icmpCodeValues *CanonicalIntervalSet) string {
	strList := []string{
		getDimensionStr(protocolsValues, protocol),
		getDimensionStr(icmpTypeValues, icmpType),
		getDimensionStr(icmpCodeValues, icmpCode),
	}
	return strings.Join(filterEmptyPropertiesStr(strList), propertySeparator)
}

func getPortBasedCubeStr(protocolsValues, srcPortsValues, dstPortsValues *CanonicalIntervalSet) string {
	strList := []string{
		getDimensionStr(protocolsValues, protocol),
		getDimensionStr(srcPortsValues, srcPort),
		getDimensionStr(dstPortsValues, dstPort),
	}
	return strings.Join(filterEmptyPropertiesStr(strList), propertySeparator)
}

func getMixedProtocolsCubeStr(protocols *CanonicalIntervalSet) string {
	// TODO: make sure other dimension values are full
	return getDimensionStr(protocols, protocol)
}

func getConnsCubeStr(cube []*CanonicalIntervalSet) string {
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

type ConnDetails ProtocolList

func getCubeAsTCPItems(cube []*CanonicalIntervalSet, protocol TcpUdpProtocol) []TcpUdp {
	tcpItemsTemp := []TcpUdp{}
	tcpItemsFinal := []TcpUdp{}
	// consider src ports
	srcPorts := cube[srcPort]
	if !srcPorts.Equal(*getDimensionDomain(srcPort)) {
		// iterate the intervals in the interval-set
		for _, interval := range srcPorts.IntervalSet {
			tcpRes := TcpUdp{Protocol: protocol, MinSourcePort: int(interval.Start), MaxSourcePort: int(interval.End)}
			tcpItemsTemp = append(tcpItemsTemp, tcpRes)
		}
	} else {
		tcpItemsTemp = append(tcpItemsTemp, TcpUdp{Protocol: protocol})
	}
	// consider dst ports
	dstPorts := cube[dstPort]
	if !dstPorts.Equal(*getDimensionDomain(dstPort)) {
		// iterate the intervals in the interval-set
		for _, interval := range dstPorts.IntervalSet {
			for _, tcpItemTemp := range tcpItemsTemp {
				tcpRes := TcpUdp{
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

func getIntervalNumbers(c *CanonicalIntervalSet) []int {
	res := []int{}
	for _, interval := range c.IntervalSet {
		for i := interval.Start; i <= interval.End; i++ {
			res = append(res, int(i))
		}
	}
	return res
}

func getCubeAsICMPItems(cube []*CanonicalIntervalSet) []Icmp {
	icmpTypes := cube[icmpType]
	icmpCodes := cube[icmpCode]
	if icmpTypes.Equal(*getDimensionDomain(icmpType)) && icmpCodes.Equal(*getDimensionDomain(icmpCode)) {
		return []Icmp{{Protocol: IcmpProtocolICMP}}
	}
	res := []Icmp{}
	if icmpTypes.Equal(*getDimensionDomain(icmpType)) {
		codeNumbers := getIntervalNumbers(icmpCodes)
		for i := range codeNumbers {
			res = append(res, Icmp{Protocol: IcmpProtocolICMP, Code: &codeNumbers[i]})
		}
		return res
	}
	if icmpCodes.Equal(*getDimensionDomain(icmpCode)) {
		typeNumbers := getIntervalNumbers(icmpTypes)
		for i := range typeNumbers {
			res = append(res, Icmp{Protocol: IcmpProtocolICMP, Type: &typeNumbers[i]})
		}
		return res
	}
	// iterate both codes and types
	typeNumbers := getIntervalNumbers(icmpTypes)
	codeNumbers := getIntervalNumbers(icmpCodes)
	for i := range typeNumbers {
		for j := range codeNumbers {
			res = append(res, Icmp{Protocol: IcmpProtocolICMP, Type: &typeNumbers[i], Code: &codeNumbers[j]})
		}
	}
	return res
}

func ConnToJSONRep(c *ConnectionSet) ConnDetails {
	if c.AllowAll {
		return ConnDetails(ProtocolList{AnyProtocol{Protocol: AnyProtocolProtocolANY}})
	}
	res := ProtocolList{}

	cubes := c.connectionProperties.GetCubesList()
	for _, cube := range cubes {
		protocols := cube[protocol]
		if protocols.Contains(TCP) {
			tcpItems := getCubeAsTCPItems(cube, TcpUdpProtocolTCP)
			for _, item := range tcpItems {
				res = append(res, item)
			}
		}
		if protocols.Contains(UDP) {
			udpItems := getCubeAsTCPItems(cube, TcpUdpProtocolUDP)
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
func copyCube(cube []*CanonicalIntervalSet) []*CanonicalIntervalSet {
	newCube := make([]*CanonicalIntervalSet, len(cube))
	for i, interval := range cube {
		newInterval := interval.Copy()
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
				res.connectionProperties = res.connectionProperties.Union(CreateFromCube(newCube))
			} else {
				res.connectionProperties = res.connectionProperties.Union(CreateFromCube(cube))
			}
		} else if protocols.Contains(ICMP) {
			res.connectionProperties = res.connectionProperties.Union(CreateFromCube(cube))
		}
	}
	return res
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
		return AllConnections
	} else if conn.IsEmpty() {
		return NoConnections
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
