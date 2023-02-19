package resources

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
)

func getSGRule(rule vpc1.SecurityGroupRuleIntf) (string, *SGRule, bool) {
	ruleRes := &SGRule{}
	var isIngress bool

	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll); ok {
		direction := *ruleObj.Direction
		isIngress = isIngressRule(ruleObj.Direction)
		protocol := *ruleObj.Protocol
		remote := ruleObj.Remote
		cidr := ""
		var target *IPBlock
		//SecurityGroupRuleRemoteCIDR
		if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemoteCIDR); ok {
			cidr = *remoteObj.CIDRBlock
			target = NewIPBlockFromCidr(cidr)
		}
		//TODO: handle other remote types:
		//SecurityGroupRuleRemoteIP
		//SecurityGroupRuleRemoteSecurityGroupReference
		ruleStr := fmt.Sprintf("direction: %s, protocol: %s, cidr: %s", direction, protocol, cidr)
		fmt.Printf("SG rule: %s\n", ruleStr)
		ruleRes.target = target
		ruleRes.connections = getAllConnSet()
		return ruleStr, ruleRes, isIngress
	}
	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp); ok {
		direction := *ruleObj.Direction
		isIngress = isIngressRule(ruleObj.Direction)
		protocol := *ruleObj.Protocol
		remote := ruleObj.Remote
		cidr := ""
		var target *IPBlock
		//TODO: handle other remote types:
		//SecurityGroupRuleRemoteIP
		//SecurityGroupRuleRemoteSecurityGroupReference
		if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemoteCIDR); ok {
			cidr = *remoteObj.CIDRBlock
			target = NewIPBlockFromCidr(cidr)
		}
		// how can infer type of remote from this object?
		// can also be Address or CRN or ...
		if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemote); ok {
			cidr = *remoteObj.CIDRBlock
			target = NewIPBlockFromCidr(cidr)
		}
		ruleStr := fmt.Sprintf("direction: %s, protocol: %s, cidr: %s", direction, protocol, cidr)
		fmt.Printf("SG rule: %s\n", ruleStr)
		ruleRes := &SGRule{}
		ruleRes.connections = getProtocolConn(ruleObj.Protocol, ruleObj.PortMax, ruleObj.PortMin)
		ruleRes.target = target
		return ruleStr, ruleRes, isIngress
	}

	return "", nil, false

}

func getSGrules(sgObj *vpc1.SecurityGroup) ([]*SGRule, []*SGRule) {
	ingressRules := []*SGRule{}
	egressRules := []*SGRule{}
	for index := range sgObj.Rules {
		rule := sgObj.Rules[index]
		_, ruleObj, isIngress := getSGRule(rule)
		if isIngress {
			ingressRules = append(ingressRules, ruleObj)
		} else {
			egressRules = append(egressRules, ruleObj)
		}
	}
	return ingressRules, egressRules
}

type SGRule struct {
	target      *IPBlock
	connections *ConnectionSet
}

//ConnecitivytResult should be built on disjoint ip-blocks for targets of all relevant sg results
type ConnecitivytResult struct {
	isIngress    bool
	allowedconns map[*IPBlock]*ConnectionSet // allowed target and its allowed connections
}

func (cr *ConnecitivytResult) union(cr2 *ConnecitivytResult) *ConnecitivytResult {
	//union based on disjoint ip-blocks of targets
	crTargets := cr.getTatgets()
	cr2Targets := cr2.getTatgets()
	disjointTargets := DisjointIPBlocks(crTargets, cr2Targets)
	res := &ConnecitivytResult{isIngress: cr.isIngress, allowedconns: map[*IPBlock]*ConnectionSet{}}
	for i := range disjointTargets {
		res.allowedconns[disjointTargets[i]] = getEmptyConnSet()
		for t, conn := range cr.allowedconns {
			if disjointTargets[i].ContainedIn(t) {
				res.allowedconns[disjointTargets[i]].Union(*conn)
			}
		}
		for t, conn := range cr2.allowedconns {
			if disjointTargets[i].ContainedIn(t) {
				res.allowedconns[disjointTargets[i]].Union(*conn)
			}
		}
	}

	return res
}

func (cr *ConnecitivytResult) string() string {
	res := ""
	for t, conn := range cr.allowedconns {
		res += fmt.Sprintf("target: %s, conn: %s", t.ToIPRanges(), conn.String())
	}
	return res
}

func (cr *ConnecitivytResult) getTatgets() []*IPBlock {
	res := []*IPBlock{}
	for t := range cr.allowedconns {
		res = append(res, t)
	}
	return res
}

func AnalyzeSGRules(rules []*SGRule, isIngress bool) *ConnecitivytResult {
	targets := []*IPBlock{}
	for i := range rules {
		targets = append(targets, rules[i].target)
	}
	disjointTargets := DisjointIPBlocks(targets, []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))})
	res := &ConnecitivytResult{isIngress: isIngress, allowedconns: map[*IPBlock]*ConnectionSet{}}
	for i := range disjointTargets {
		res.allowedconns[disjointTargets[i]] = getEmptyConnSet()
	}
	for i := range rules {
		rule := rules[i]
		target := rule.target
		conn := rule.connections
		for disjointTarget := range res.allowedconns {
			if disjointTarget.ContainedIn(target) {
				res.allowedconns[disjointTarget].Union(*conn)
			}

		}
	}

	return res

}

// get allowed connections (ingress and egress) based on the list of SG that are applied to it
func AnalyzeSGListPerInstance(vsiIP *IPBlock, sgList []*vpc1.SecurityGroup) (string, string) {
	var accumulatedIngressRes *ConnecitivytResult
	var accumulatedEgressRes *ConnecitivytResult
	for _, sg := range sgList {
		ingressRules, egressRules := getSGrules(sg)
		ingressRes := AnalyzeSGRules(ingressRules, true)
		egressRes := AnalyzeSGRules(egressRules, false)
		accumulatedIngressRes = accumulatedIngressRes.union(ingressRes)
		accumulatedEgressRes = accumulatedEgressRes.union(egressRes)
	}
	return accumulatedIngressRes.string(), accumulatedEgressRes.string()
}

// next: get allowed connectivity per vsi interface considering both nacl and sg (intersection of allowed connectivity from both layers)

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
