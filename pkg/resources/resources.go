package resources

import (
	"fmt"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
	v1 "k8s.io/api/core/v1"

	"encoding/json"
)

///////////////////////////////////////////////////////////////////////////////////////////////

// convert json string of nacl to vpc1.NetworkACL object
func JsonNaclToObject(nwacl []byte) *vpc1.NetworkACL {
	naclMap := jsonToMap(nwacl)
	naclObj := &vpc1.NetworkACL{}
	vpc1.UnmarshalNetworkACL(naclMap, &naclObj)
	return naclObj
}

// convert vpc1.NetworkACL to json string
func ObjectNaclToJson(naclObj *vpc1.NetworkACL) ([]byte, error) {
	// return json.Marshal(*naclObj)
	return json.MarshalIndent(*naclObj, "", "    ")
}

// convert json string to map object
func jsonToMap(jsonStr []byte) map[string]json.RawMessage {
	var result map[string]json.RawMessage
	json.Unmarshal(jsonStr, &result)
	return result
}

func getNACLRule(rule vpc1.NetworkACLRuleItemIntf) (string, *Rule, bool) {
	ruleRes := Rule{}
	var isIngress bool

	if ruleObj, ok := rule.(*vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll); ok {
		res := fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n", *ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, *ruleObj.Protocol, *ruleObj.Action)
		// convert to rule object
		srcIP, _ := NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := NewIPBlock(*ruleObj.Destination, []string{})
		conns := MakeConnectionSet(true)
		ruleRes = Rule{src: srcIP, dst: dstIP, connections: &conns, action: *ruleObj.Action}
		if *ruleObj.Direction == "inbound" {
			isIngress = true
		} else if *ruleObj.Direction == "outbound" {
			isIngress = false
		}
		return res, &ruleRes, isIngress
	} else if ruleObj, ok := rule.(*vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp); ok {
		srcPorts := fmt.Sprintf("%d-%d", *ruleObj.SourcePortMin, *ruleObj.SourcePortMax)
		dstPorts := fmt.Sprintf("%d-%d", *ruleObj.DestinationPortMin, *ruleObj.DestinationPortMax)
		connStr := fmt.Sprintf("protocol: %s, srcPorts: %s, dstPorts: %s", *ruleObj.Protocol, srcPorts, dstPorts)
		res := fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n", *ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, connStr, *ruleObj.Action)

		// convert to rule object
		// TODO: currently ignoring src ports in the conversion
		srcIP, _ := NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := NewIPBlock(*ruleObj.Destination, []string{})
		conns := MakeConnectionSet(false)
		ports := PortSet{Ports: CanonicalIntervalSet{IntervalSet: []Interval{{Start: *ruleObj.DestinationPortMin, End: *ruleObj.DestinationPortMax}}}}
		if *ruleObj.Protocol == "tcp" {
			conns.AllowedProtocols[v1.ProtocolTCP] = &ports
		} else if *ruleObj.Protocol == "udp" {
			conns.AllowedProtocols[v1.ProtocolUDP] = &ports
		}

		ruleRes = Rule{src: srcIP, dst: dstIP, connections: &conns, action: *ruleObj.Action}
		if *ruleObj.Direction == "inbound" {
			isIngress = true
		} else if *ruleObj.Direction == "outbound" {
			isIngress = false
		}
		return res, &ruleRes, isIngress
		//return res, nil, false
	} else if ruleObj, ok := rule.(*vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp); ok {
		connStr := fmt.Sprintf("protocol: %s, type: %d, code: %d", *ruleObj.Protocol, *ruleObj.Type, *ruleObj.Code)
		res := fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n", *ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, connStr, *ruleObj.Action)

		// TODO: currently ignoring icmp rules and not converting to rule object

		return res, nil, false
	}
	return "", nil, false
}

type Rule struct {
	src         *IPBlock
	dst         *IPBlock
	connections *ConnectionSet
	action      string
}

func getEmptyConnSet() *ConnectionSet {
	res := MakeConnectionSet(false)
	return &res
}

func getAllConnSet() *ConnectionSet {
	res := MakeConnectionSet(true)
	return &res
}

// given ingress rules from NACL , specific src, subnet cidr and disjoint peers of dest ip-blocks -- get the allowed connections
func getAllowedXgressConnections(rules []*Rule, src *IPBlock, subnetCidr *IPBlock, disjointPeers []*IPBlock, isIngress bool) map[string]*ConnectionSet {
	allowedIngress := map[string]*ConnectionSet{}
	deniedIngress := map[string]*ConnectionSet{}
	for _, cidr := range disjointPeers {
		if cidr.ContainedIn(subnetCidr) {
			allowedIngress[cidr.ToIPRanges()] = getEmptyConnSet()
			deniedIngress[cidr.ToIPRanges()] = getEmptyConnSet()
		}
	}

	if src.ContainedIn(subnetCidr) {
		//no need to check nacl rules for connections within the subnet
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(subnetCidr) {
				allowedIngress[cidr.ToIPRanges()] = getAllConnSet()
			}
		}
		return allowedIngress
	}

	for _, ingressRule := range rules {
		var s *IPBlock
		var d *IPBlock
		if isIngress {
			s = ingressRule.src
			d = ingressRule.dst
		} else {
			s = ingressRule.dst
			d = ingressRule.src
		}
		if !src.ContainedIn(s) {
			continue
		}
		destCidr := d.Intersection(subnetCidr)
		// split destCidr to disjoint ip-blocks
		destCidrList := []*IPBlock{}
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(destCidr) {
				destCidrList = append(destCidrList, cidr)
			}
		}
		for _, disjointDestCidr := range destCidrList {
			if ingressRule.action == "allow" {
				addedAllowedConns := *ingressRule.connections.Copy()
				addedAllowedConns.Subtract(*deniedIngress[disjointDestCidr.ToIPRanges()])
				allowedIngress[disjointDestCidr.ToIPRanges()].Union(addedAllowedConns)
			} else if ingressRule.action == "deny" {
				addedDeniedConns := *ingressRule.connections.Copy()
				addedDeniedConns.Subtract(*allowedIngress[disjointDestCidr.ToIPRanges()])
				deniedIngress[disjointDestCidr.ToIPRanges()].Union(addedDeniedConns)
			}
		}
	}
	return allowedIngress
}

func getDisjointPeers(rules []*Rule, subnet *IPBlock) ([]*IPBlock, []*IPBlock) {
	srcPeers := []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))}
	dstPeers := []*IPBlock{subnet}
	peers := []*IPBlock{subnet}
	for _, rule := range rules {
		peers = append(peers, rule.src)
		peers = append(peers, rule.dst)
		srcPeers = append(srcPeers, rule.src)
		dstPeers = append(dstPeers, rule.dst)
	}
	return DisjointIPBlocks(srcPeers, []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))}), DisjointIPBlocks(dstPeers, []*IPBlock{subnet})
}

func getDisjointPeersNew(rules []*Rule, subnet *IPBlock) ([]*IPBlock, []*IPBlock) {
	dstPeers := []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))}
	srcPeers := []*IPBlock{subnet}
	peers := []*IPBlock{subnet}
	for _, rule := range rules {
		peers = append(peers, rule.src)
		peers = append(peers, rule.dst)
		srcPeers = append(srcPeers, rule.src)
		dstPeers = append(dstPeers, rule.dst)
	}
	return DisjointIPBlocks(srcPeers, []*IPBlock{subnet}), DisjointIPBlocks(dstPeers, []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))})
}

//get ingress and egress rules from NACL obj
func getNACLRules(naclObj *vpc1.NetworkACL) ([]*Rule, []*Rule) {
	ingressRules := []*Rule{}
	egressRules := []*Rule{}
	for index := range naclObj.Rules {
		rule := naclObj.Rules[index]
		_, ruleObj, isIngress := getNACLRule(rule)
		if rule == nil {
			continue
		}
		if isIngress {
			ingressRules = append(ingressRules, ruleObj)
		} else {
			egressRules = append(egressRules, ruleObj)
		}
	}
	return ingressRules, egressRules
}

// get allowed and denied connections (ingress and egress) for a certain subnet to which this nacl is applied
func AnalyzeNACL(naclObj *vpc1.NetworkACL, subnet *IPBlock) (string, string) {
	ingressRules, egressRules := getNACLRules(naclObj)
	ingressRes := AnalyzeNACLRules(ingressRules, subnet, true)
	egressRes := AnalyzeNACLRules(egressRules, subnet, false)
	return ingressRes, egressRes
}

func AnalyzeNACLRules(rules []*Rule, subnet *IPBlock, isIngress bool) string {

	res := []string{}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeers(rules, subnet)
		// ingress
		for _, src := range disjointSrcPeers {
			allowedIngressConns := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				res = append(res, fmt.Sprintf("%s => %s : %s\n", src.ToIPRanges(), dst, conn.String()))
			}
		}
		return strings.Join(res, "")
	}
	// egress
	disjointSrcPeers, disjointDstPeers := getDisjointPeersNew(rules, subnet)
	for _, dst := range disjointDstPeers {
		allowedEgressConns := getAllowedXgressConnections(rules, dst, subnet, disjointSrcPeers, false)
		for src, conn := range allowedEgressConns {
			res = append(res, fmt.Sprintf("%s => %s : %s\n", src, dst.ToIPRanges(), conn.String()))
		}
	}
	return strings.Join(res, "")

}

func Test() {

}

/*

relevant unmarshal functions:
UnmarshalNetworkACL
UnmarshalSecurityGroup
UnmarshalSubnet
UnmarshalVPC




// NetworkACLRuleItem : NetworkACLRuleItem struct
// Models which "extend" this model:
// - NetworkACLRuleItemNetworkACLRuleProtocolTcpudp
// - NetworkACLRuleItemNetworkACLRuleProtocolIcmp
// - NetworkACLRuleItemNetworkACLRuleProtocolAll
type NetworkACLRuleItem struct {
	// The action to perform for a packet matching the rule.
	Action *string `json:"action" validate:"required"`

	// The rule that this rule is immediately before. In a rule collection, this always
	// refers to the next item in the collection. If absent, this is the last rule.
	Before *NetworkACLRuleReference `json:"before,omitempty"`

	// The date and time that the rule was created.
	CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`

	// The destination IP address or CIDR block to match. The CIDR block `0.0.0.0/0` matches all destination addresses.
	Destination *string `json:"destination" validate:"required"`

	// The direction of traffic to match.
	Direction *string `json:"direction" validate:"required"`

	// The URL for this network ACL rule.
	Href *string `json:"href" validate:"required"`

	// The unique identifier for this network ACL rule.
	ID *string `json:"id" validate:"required"`

	// The IP version for this rule.
	IPVersion *string `json:"ip_version" validate:"required"`

	// The name for this network ACL rule. The name is unique across all rules for the network ACL.
	Name *string `json:"name" validate:"required"`

	// The protocol to enforce.
	Protocol *string `json:"protocol" validate:"required"`

	// The source IP address or CIDR block to match. The CIDR block `0.0.0.0/0` matches all source addresses.
	Source *string `json:"source" validate:"required"`

	// The inclusive upper bound of TCP/UDP destination port range.
	DestinationPortMax *int64 `json:"destination_port_max,omitempty"`

	// The inclusive lower bound of TCP/UDP destination port range.
	DestinationPortMin *int64 `json:"destination_port_min,omitempty"`

	// The inclusive upper bound of TCP/UDP source port range.
	SourcePortMax *int64 `json:"source_port_max,omitempty"`

	// The inclusive lower bound of TCP/UDP source port range.
	SourcePortMin *int64 `json:"source_port_min,omitempty"`

	// The ICMP traffic code to match.
	//
	// If absent, all codes are matched.
	Code *int64 `json:"code,omitempty"`

	// The ICMP traffic type to match.
	//
	// If absent, all types are matched.
	Type *int64 `json:"type,omitempty"`
}

// Constants associated with the NetworkACLRuleItem.Action property.
// The action to perform for a packet matching the rule.
const (
	NetworkACLRuleItemActionAllowConst = "allow"
	NetworkACLRuleItemActionDenyConst  = "deny"
)




// NetworkACLRuleNetworkACLRuleProtocolTcpudp : NetworkACLRuleNetworkACLRuleProtocolTcpudp struct
// This model "extends" NetworkACLRule
type NetworkACLRuleNetworkACLRuleProtocolTcpudp struct {
	// The action to perform for a packet matching the rule.
	Action *string `json:"action" validate:"required"`

	// The rule that this rule is immediately before. If absent, this is the last rule.
	Before *NetworkACLRuleReference `json:"before,omitempty"`

	// The date and time that the rule was created.
	CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`

	// The destination IP address or CIDR block to match. The CIDR block `0.0.0.0/0` matches all destination addresses.
	Destination *string `json:"destination" validate:"required"`

	// The direction of traffic to match.
	Direction *string `json:"direction" validate:"required"`

	// The URL for this network ACL rule.
	Href *string `json:"href" validate:"required"`

	// The unique identifier for this network ACL rule.
	ID *string `json:"id" validate:"required"`

	// The IP version for this rule.
	IPVersion *string `json:"ip_version" validate:"required"`

	// The name for this network ACL rule. The name is unique across all rules for the network ACL.
	Name *string `json:"name" validate:"required"`

	// The source IP address or CIDR block to match. The CIDR block `0.0.0.0/0` matches all source addresses.
	Source *string `json:"source" validate:"required"`

	// The inclusive upper bound of TCP/UDP destination port range.
	DestinationPortMax *int64 `json:"destination_port_max" validate:"required"`

	// The inclusive lower bound of TCP/UDP destination port range.
	DestinationPortMin *int64 `json:"destination_port_min" validate:"required"`

	// The protocol to enforce.
	Protocol *string `json:"protocol" validate:"required"`

	// The inclusive upper bound of TCP/UDP source port range.
	SourcePortMax *int64 `json:"source_port_max" validate:"required"`

	// The inclusive lower bound of TCP/UDP source port range.
	SourcePortMin *int64 `json:"source_port_min" validate:"required"`
}

==============================================================================


// NetworkACLRule : NetworkACLRule struct
// Models which "extend" this model:
// - NetworkACLRuleNetworkACLRuleProtocolTcpudp
// - NetworkACLRuleNetworkACLRuleProtocolIcmp
// - NetworkACLRuleNetworkACLRuleProtocolAll
type NetworkACLRule struct {
	// The action to perform for a packet matching the rule.
	Action *string `json:"action" validate:"required"`

	// The rule that this rule is immediately before. If absent, this is the last rule.
	Before *NetworkACLRuleReference `json:"before,omitempty"`

	// The date and time that the rule was created.
	CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`

	// The destination IP address or CIDR block to match. The CIDR block `0.0.0.0/0` matches all destination addresses.
	Destination *string `json:"destination" validate:"required"`

	// The direction of traffic to match.
	Direction *string `json:"direction" validate:"required"`

	// The URL for this network ACL rule.
	Href *string `json:"href" validate:"required"`

	// The unique identifier for this network ACL rule.
	ID *string `json:"id" validate:"required"`

	// The IP version for this rule.
	IPVersion *string `json:"ip_version" validate:"required"`

	// The name for this network ACL rule. The name is unique across all rules for the network ACL.
	Name *string `json:"name" validate:"required"`

	// The protocol to enforce.
	Protocol *string `json:"protocol" validate:"required"`

	// The source IP address or CIDR block to match. The CIDR block `0.0.0.0/0` matches all source addresses.
	Source *string `json:"source" validate:"required"`

	// The inclusive upper bound of TCP/UDP destination port range.
	DestinationPortMax *int64 `json:"destination_port_max,omitempty"`

	// The inclusive lower bound of TCP/UDP destination port range.
	DestinationPortMin *int64 `json:"destination_port_min,omitempty"`

	// The inclusive upper bound of TCP/UDP source port range.
	SourcePortMax *int64 `json:"source_port_max,omitempty"`

	// The inclusive lower bound of TCP/UDP source port range.
	SourcePortMin *int64 `json:"source_port_min,omitempty"`

	// The ICMP traffic code to match.
	//
	// If absent, all codes are matched.
	Code *int64 `json:"code,omitempty"`

	// The ICMP traffic type to match.
	//
	// If absent, all types are matched.
	Type *int64 `json:"type,omitempty"`
}


==============================================================================

// NetworkACL : NetworkACL struct
type NetworkACL struct {
	// The date and time that the network ACL was created.
	CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`

	// The CRN for this network ACL.
	CRN *string `json:"crn" validate:"required"`

	// The URL for this network ACL.
	Href *string `json:"href" validate:"required"`

	// The unique identifier for this network ACL.
	ID *string `json:"id" validate:"required"`

	// The name for this network ACL. The name is unique across all network ACLs for the VPC.
	Name *string `json:"name" validate:"required"`

	// The resource group for this network ACL.
	ResourceGroup *ResourceGroupReference `json:"resource_group" validate:"required"`

	// The ordered rules for this network ACL. If no rules exist, all traffic will be denied.
	Rules []NetworkACLRuleItemIntf `json:"rules" validate:"required"`

	// The subnets to which this network ACL is attached.
	Subnets []SubnetReference `json:"subnets" validate:"required"`

	// The VPC this network ACL resides in.
	VPC *VPCReference `json:"vpc" validate:"required"`
}

==============================================================================

// Subnet : Subnet struct
type Subnet struct {
	// The number of IPv4 addresses in this subnet that are not in-use, and have not been reserved by the user or the
	// provider.
	AvailableIpv4AddressCount *int64 `json:"available_ipv4_address_count" validate:"required"`

	// The date and time that the subnet was created.
	CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`

	// The CRN for this subnet.
	CRN *string `json:"crn" validate:"required"`

	// The URL for this subnet.
	Href *string `json:"href" validate:"required"`

	// The unique identifier for this subnet.
	ID *string `json:"id" validate:"required"`

	// The IP version(s) supported by this subnet.
	IPVersion *string `json:"ip_version" validate:"required"`

	// The IPv4 range of the subnet, expressed in CIDR format.
	Ipv4CIDRBlock *string `json:"ipv4_cidr_block" validate:"required"`

	// The name for this subnet. The name is unique across all subnets in the VPC.
	Name *string `json:"name" validate:"required"`

	// The network ACL for this subnet.
	NetworkACL *NetworkACLReference `json:"network_acl" validate:"required"`

	// The public gateway to use for internet-bound traffic for this subnet.
	PublicGateway *PublicGatewayReference `json:"public_gateway,omitempty"`

	// The resource group for this subnet.
	ResourceGroup *ResourceGroupReference `json:"resource_group" validate:"required"`

	// The resource type.
	ResourceType *string `json:"resource_type" validate:"required"`

	// The routing table for this subnet.
	RoutingTable *RoutingTableReference `json:"routing_table" validate:"required"`

	// The status of the subnet.
	Status *string `json:"status" validate:"required"`

	// The total number of IPv4 addresses in this subnet.
	//
	// Note: This is calculated as 2<sup>(32 - prefix length)</sup>. For example, the prefix length `/24` gives:<br>
	// 2<sup>(32 - 24)</sup> = 2<sup>8</sup> = 256 addresses.
	TotalIpv4AddressCount *int64 `json:"total_ipv4_address_count" validate:"required"`

	// The VPC this subnet resides in.
	VPC *VPCReference `json:"vpc" validate:"required"`

	// The zone this subnet resides in.
	Zone *ZoneReference `json:"zone" validate:"required"`
}
*/
