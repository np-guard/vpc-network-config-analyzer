package resources

import (
	"encoding/json"
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
)

func JsonSgToObject(sg []byte) *vpc1.SecurityGroup {
	sgMap := jsonToMap(sg)
	sgObj := &vpc1.SecurityGroup{}
	vpc1.UnmarshalSecurityGroup(sgMap, &sgObj)
	return sgObj
}

// convert vpc1.SecurityGroup to json string
func ObjectSgToJson(sgObj *vpc1.SecurityGroup) ([]byte, error) {
	// return json.Marshal(*naclObj)
	return json.MarshalIndent(*sgObj, "", "    ")
}

func getSGRule(rule vpc1.SecurityGroupRuleIntf) (string, *Rule, bool) {
	//ruleRes := Rule{}
	//var isIngress bool

	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll); ok {
		direction := *ruleObj.Direction
		protocol := *ruleObj.Protocol
		remote := ruleObj.Remote
		cidr := ""
		if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemoteCIDR); ok {
			cidr = *remoteObj.CIDRBlock
		}
		ruleStr := fmt.Sprintf("direction: %s, protocol: %s, cidr: %s", direction, protocol, cidr)
		fmt.Printf("SG rule: %s\n", ruleStr)
		ruleRes := &Rule{}
		return ruleStr, ruleRes, true
	}
	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp); ok {
		direction := *ruleObj.Direction
		protocol := *ruleObj.Protocol
		remote := ruleObj.Remote
		cidr := ""
		if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemoteCIDR); ok {
			cidr = *remoteObj.CIDRBlock
		}
		// how can infer type of remote from this object?
		// can also be Address or CRN or ...
		if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemote); ok {
			cidr = *remoteObj.CIDRBlock
		}
		ruleStr := fmt.Sprintf("direction: %s, protocol: %s, cidr: %s", direction, protocol, cidr)
		fmt.Printf("SG rule: %s\n", ruleStr)
		ruleRes := &Rule{}
		return ruleStr, ruleRes, true
	}

	return "", nil, false

}

func getSGrules(sgObj *vpc1.SecurityGroup) {
	for index := range sgObj.Rules {
		rule := sgObj.Rules[index]
		//_, ruleObj, isIngress := getSGRule(rule)
		getSGRule(rule)
	}
}

//sg1 fields objects:
//github.com/IBM/vpc-go-sdk/vpcv1.SecurityGroupRuleIntf(*github.com/IBM/vpc-go-sdk/vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp) *{Direction: *"inbound", Href: *"https://us-south.iaas.cloud.ibm.com/v1/security_groups/2d364f0a-a870-42c3-a554-000001099037/rules/b597cff2-38e8-4e6e-999d-000002172691", ID: *"b597cff2-38e8-4e6e-999d-000002172691", IPVersion: *"ipv4", Remote: github.com/IBM/vpc-go-sdk/vpcv1.SecurityGroupRuleRemoteIntf(*github.com/IBM/vpc-go-sdk/vpcv1.SecurityGroupRuleRemote) *{Address: *string nil, CIDRBlock: *"0.0.0.0/0", CRN: *string nil, Deleted: *github.com/IBM/vpc-go-sdk/vpcv1.SecurityGroupReferenceDeleted nil, Href: *string nil, ID: *string nil, Name: *string nil}, PortMax: *22, PortMin: *22, Protocol: *"tcp"}
//github.com/IBM/vpc-go-sdk/vpcv1.SecurityGroupRuleRemoteIntf(*github.com/IBM/vpc-go-sdk/vpcv1.SecurityGroupRuleRemote) *{Address: *string nil, CIDRBlock: *"0.0.0.0/0", CRN: *string nil, Deleted: *github.com/IBM/vpc-go-sdk/vpcv1.SecurityGroupReferenceDeleted nil, Href: *string nil, ID: *string nil, Name: *string nil}

/*
// SecurityGroupRuleRemote : The IP addresses or security groups from which this rule allows traffic (or to which, for outbound rules). Can be
// specified as an IP address, a CIDR block, or a security group. A CIDR block of `0.0.0.0/0` allows traffic from any
// source (or to any destination, for outbound rules).
// Models which "extend" this model:
// - SecurityGroupRuleRemoteIP
// - SecurityGroupRuleRemoteCIDR
// - SecurityGroupRuleRemoteSecurityGroupReference
type SecurityGroupRuleRemote struct {
	// The IP address.
	//
	// This property may add support for IPv6 addresses in the future. When processing a value in this property, verify
	// that the address is in an expected format. If it is not, log an error. Optionally halt processing and surface the
	// error, or bypass the resource on which the unexpected IP address format was encountered.
	Address *string `json:"address,omitempty"`

	// The CIDR block. This property may add support for IPv6 CIDR blocks in the future. When processing a value in this
	// property, verify that the CIDR block is in an expected format. If it is not, log an error. Optionally halt
	// processing and surface the error, or bypass the resource on which the unexpected CIDR block format was encountered.
	CIDRBlock *string `json:"cidr_block,omitempty"`

	// The security group's CRN.
	CRN *string `json:"crn,omitempty"`

	// If present, this property indicates the referenced resource has been deleted, and provides
	// some supplementary information.
	Deleted *SecurityGroupReferenceDeleted `json:"deleted,omitempty"`

	// The security group's canonical URL.
	Href *string `json:"href,omitempty"`

	// The unique identifier for this security group.
	ID *string `json:"id,omitempty"`

	// The name for this security group. The name is unique across all security groups for the VPC.
	Name *string `json:"name,omitempty"`
}



// SecurityGroupRuleRemotePrototype : The IP addresses or security groups from which this rule will allow traffic (or to which, for outbound rules). Can be
// specified as an IP address, a CIDR block, or a security group within the VPC.
//
// If unspecified, a CIDR block of `0.0.0.0/0` will be used to allow traffic from any source
// (or to any destination, for outbound rules).
// Models which "extend" this model:
// - SecurityGroupRuleRemotePrototypeIP
// - SecurityGroupRuleRemotePrototypeCIDR
// - SecurityGroupRuleRemotePrototypeSecurityGroupIdentity
type SecurityGroupRuleRemotePrototype struct {
	// The IP address.
	//
	// This property may add support for IPv6 addresses in the future. When processing a value in this property, verify
	// that the address is in an expected format. If it is not, log an error. Optionally halt processing and surface the
	// error, or bypass the resource on which the unexpected IP address format was encountered.
	Address *string `json:"address,omitempty"`

	// The CIDR block. This property may add support for IPv6 CIDR blocks in the future. When processing a value in this
	// property, verify that the CIDR block is in an expected format. If it is not, log an error. Optionally halt
	// processing and surface the error, or bypass the resource on which the unexpected CIDR block format was encountered.
	CIDRBlock *string `json:"cidr_block,omitempty"`

	// The unique identifier for this security group.
	ID *string `json:"id,omitempty"`

	// The security group's CRN.
	CRN *string `json:"crn,omitempty"`

	// The security group's canonical URL.
	Href *string `json:"href,omitempty"`
}



// SecurityGroupRuleRemoteIP : SecurityGroupRuleRemoteIP struct
// This model "extends" SecurityGroupRuleRemote
type SecurityGroupRuleRemoteIP struct {
	// The IP address.
	//
	// This property may add support for IPv6 addresses in the future. When processing a value in this property, verify
	// that the address is in an expected format. If it is not, log an error. Optionally halt processing and surface the
	// error, or bypass the resource on which the unexpected IP address format was encountered.
	Address *string `json:"address" validate:"required"`
}


// SecurityGroupRuleRemoteCIDR : SecurityGroupRuleRemoteCIDR struct
// This model "extends" SecurityGroupRuleRemote
type SecurityGroupRuleRemoteCIDR struct {
	// The CIDR block. This property may add support for IPv6 CIDR blocks in the future. When processing a value in this
	// property, verify that the CIDR block is in an expected format. If it is not, log an error. Optionally halt
	// processing and surface the error, or bypass the resource on which the unexpected CIDR block format was encountered.
	CIDRBlock *string `json:"cidr_block" validate:"required"`
}


// SecurityGroupRuleRemotePrototypeSecurityGroupIdentity : Identifies a security group by a unique property.
// Models which "extend" this model:
// - SecurityGroupRuleRemotePrototypeSecurityGroupIdentitySecurityGroupIdentityByID
// - SecurityGroupRuleRemotePrototypeSecurityGroupIdentitySecurityGroupIdentityByCRN
// - SecurityGroupRuleRemotePrototypeSecurityGroupIdentitySecurityGroupIdentityByHref
// This model "extends" SecurityGroupRuleRemotePrototype
type SecurityGroupRuleRemotePrototypeSecurityGroupIdentity struct {
	// The unique identifier for this security group.
	ID *string `json:"id,omitempty"`

	// The security group's CRN.
	CRN *string `json:"crn,omitempty"`

	// The security group's canonical URL.
	Href *string `json:"href,omitempty"`
}



// SecurityGroupRuleRemotePrototypeIP : SecurityGroupRuleRemotePrototypeIP struct
// This model "extends" SecurityGroupRuleRemotePrototype
type SecurityGroupRuleRemotePrototypeIP struct {
	// The IP address.
	//
	// This property may add support for IPv6 addresses in the future. When processing a value in this property, verify
	// that the address is in an expected format. If it is not, log an error. Optionally halt processing and surface the
	// error, or bypass the resource on which the unexpected IP address format was encountered.
	Address *string `json:"address" validate:"required"`
}



-------------------------------------------------------------------


// SecurityGroupRule : SecurityGroupRule struct
// Models which "extend" this model:
// - SecurityGroupRuleSecurityGroupRuleProtocolAll
// - SecurityGroupRuleSecurityGroupRuleProtocolIcmp
// - SecurityGroupRuleSecurityGroupRuleProtocolTcpudp
type SecurityGroupRule struct {
	// The direction of traffic to enforce.
	Direction *string `json:"direction" validate:"required"`

	// The URL for this security group rule.
	Href *string `json:"href" validate:"required"`

	// The unique identifier for this security group rule.
	ID *string `json:"id" validate:"required"`

	// The IP version to enforce. The format of `remote.address` or `remote.cidr_block` must match this property, if they
	// are used. Alternatively, if `remote` references a security group, then this rule only applies to IP addresses
	// (network interfaces) in that group matching this IP version.
	IPVersion *string `json:"ip_version" validate:"required"`

	// The protocol to enforce.
	Protocol *string `json:"protocol" validate:"required"`

	// The IP addresses or security groups from which this rule allows traffic (or to which, for
	// outbound rules). Can be specified as an IP address, a CIDR block, or a security group. A
	// CIDR block of `0.0.0.0/0` allows traffic from any source (or to any destination, for
	// outbound rules).
	Remote SecurityGroupRuleRemoteIntf `json:"remote" validate:"required"`

	// The ICMP traffic code to allow. If absent, all codes are allowed.
	Code *int64 `json:"code,omitempty"`

	// The ICMP traffic type to allow. If absent, all types are allowed.
	Type *int64 `json:"type,omitempty"`

	// The inclusive upper bound of TCP/UDP port range.
	PortMax *int64 `json:"port_max,omitempty"`

	// The inclusive lower bound of TCP/UDP port range.
	PortMin *int64 `json:"port_min,omitempty"`
}

// Constants associated with the SecurityGroupRule.Direction property.
// The direction of traffic to enforce.
const (
	SecurityGroupRuleDirectionInboundConst  = "inbound"
	SecurityGroupRuleDirectionOutboundConst = "outbound"
)

// Constants associated with the SecurityGroupRule.IPVersion property.
// The IP version to enforce. The format of `remote.address` or `remote.cidr_block` must match this property, if they
// are used. Alternatively, if `remote` references a security group, then this rule only applies to IP addresses
// (network interfaces) in that group matching this IP version.
const (
	SecurityGroupRuleIPVersionIpv4Const = "ipv4"
)

// Constants associated with the SecurityGroupRule.Protocol property.
// The protocol to enforce.
const (
	SecurityGroupRuleProtocolAllConst  = "all"
	SecurityGroupRuleProtocolIcmpConst = "icmp"
	SecurityGroupRuleProtocolTCPConst  = "tcp"
	SecurityGroupRuleProtocolUDPConst  = "udp"
)

*/
