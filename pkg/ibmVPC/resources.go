package ibmvpc

import (
	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"encoding/json"
)

///////////////////////////////////////////////////////////////////////////////////////////////

const (
	indent = "    "
)

func JSONSgToObject(sg []byte) (*vpc1.SecurityGroup, error) {
	sgMap, err := JSONToMap(sg)
	if err != nil {
		return nil, err
	}
	sgObj := &vpc1.SecurityGroup{}
	err = vpc1.UnmarshalSecurityGroup(sgMap, &sgObj)
	return sgObj, err
}

// convert vpc1.SecurityGroup to json string
func ObjectSgToJSON(sgObj *vpc1.SecurityGroup) ([]byte, error) {
	return json.MarshalIndent(*sgObj, "", indent)
}

// convert json string of nacl to vpc1.NetworkACL object
func JSONNaclToObject(nwacl []byte) (*vpc1.NetworkACL, error) {
	naclMap, err := JSONToMap(nwacl)
	if err != nil {
		return nil, err
	}
	naclObj := &vpc1.NetworkACL{}
	err = vpc1.UnmarshalNetworkACL(naclMap, &naclObj)
	return naclObj, err
}

// vsi conversion
func JSONInstanceToObject(instance []byte) (*vpc1.Instance, error) {
	instanceMap, err := JSONToMap(instance)
	if err != nil {
		return nil, err
	}
	instanceObj := &vpc1.Instance{}
	err = vpc1.UnmarshalInstance(instanceMap, &instanceObj)
	return instanceObj, err
}

// subnet conversion
func JSONSubnetToObject(subnet []byte) (*vpc1.Subnet, error) {
	subnetMap, err := JSONToMap(subnet)
	if err != nil {
		return nil, err
	}
	subnetObj := &vpc1.Subnet{}
	err = vpc1.UnmarshalSubnet(subnetMap, &subnetObj)
	return subnetObj, err
}

// vpc conversion
func JSONVpcToObject(vpc []byte) (*vpc1.VPC, error) {
	vpcMap, err := JSONToMap(vpc)
	if err != nil {
		return nil, err
	}
	vpcObj := &vpc1.VPC{}
	err = vpc1.UnmarshalVPC(vpcMap, &vpcObj)
	return vpcObj, err
}

func JSONFipToObject(fip []byte) (*vpc1.FloatingIP, error) {
	jsonMap, err := JSONToMap(fip)
	if err != nil {
		return nil, err
	}
	fipObj := &vpc1.FloatingIP{}
	err = vpc1.UnmarshalFloatingIP(jsonMap, &fipObj)
	return fipObj, err
}

func JSONPgwTpObject(pgw []byte) (*vpc1.PublicGateway, error) {
	jsonMap, err := JSONToMap(pgw)
	if err != nil {
		return nil, err
	}
	pgwObj := &vpc1.PublicGateway{}
	err = vpc1.UnmarshalPublicGateway(jsonMap, &pgwObj)
	return pgwObj, err
}

// convert vpc1.NetworkACL to json string
func ObjectNaclToJSON(naclObj *vpc1.NetworkACL) ([]byte, error) {
	return json.MarshalIndent(*naclObj, "", indent)
}

// convert json string to map object
func JSONToMap(jsonStr []byte) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	err := json.Unmarshal(jsonStr, &result)
	return result, err
}

func JSONToList(jsonStr []byte) ([]json.RawMessage, error) {
	var result []json.RawMessage
	err := json.Unmarshal(jsonStr, &result)
	return result, err
}

///////////////////////////////////////////////////////////////////////////////////////////////

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
