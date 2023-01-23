package resources

import (
	"fmt"

	_ "embed"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"encoding/json"
)

//go:embed nwacl_1.json
var b []byte

func Test() {
	v := vpc1.VpcV1{}
	fmt.Printf("%+v", v)

	print(string(b))

	n := vpc1.NetworkACL{}

	/*
			--- FAIL: TestBasic (0.00s)
				panic: json: cannot unmarshal object into Go struct field NetworkACL.rules of type vpcv1.NetworkACLRuleItemIntf [recovered]
		        panic: json: cannot unmarshal object into Go struct field NetworkACL.rules of type vpcv1.NetworkACLRuleItemIntf

	*/

	if err := json.Unmarshal(b, &n); err != nil {
		panic(err)
	}
	//fmt.Println(n)
	fmt.Printf("%+v", n)

}

/*

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
