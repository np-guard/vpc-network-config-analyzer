package vpcmodel

import "errors"

// VPCConfig captures the configured resources for a VPC
type VPCConfig struct {
	// Nodes is the list of endpoints in the VPC, such as network interfaces, reserved IPs
	Nodes []Node
	// NodeSets is the list of resources that capture multiple nodes, such as subnets, vsis, vpc
	NodeSets []NodeSet
	// FilterResources is the list of resources that define filtering traffic rules, such as ACL, SG
	FilterResources []FilterTrafficResource
	// RoutingResources is the list of resources that enable certain types of connectivity, such as PGW, FIP
	RoutingResources []RoutingResource
	// NameToResource is a map from resource UID to its object in the VPC
	NameToResource map[string]VPCResourceIntf
	CloudName      string
	// VPC is a reference to the relevant VPC object for which this config belongs
	VPC VPCResourceIntf
	// IsMultipleVPCsConfig is a bool indicator, when set true, it means that the VPCConfig contains resources from
	// multiple VPCs connected to each other, and such config is relevant for reasoning about cross-vpc connectivity
	IsMultipleVPCsConfig bool
}

// TODO: consider add this mapping to VPCConfig
func (c *VPCConfig) getSubnetOfNode(n Node) NodeSet {
	for _, nodeSet := range c.NodeSets {
		if nodeSet.Kind() == subnetKind {
			subnetNodes := nodeSet.Nodes()
			if HasNode(subnetNodes, n) {
				return nodeSet
			}
		}
	}
	return nil
}

func (c *VPCConfig) getFilterTrafficResourceOfKind(kind string) FilterTrafficResource {
	for _, filter := range c.FilterResources {
		if filter.Kind() == kind {
			return filter
		}
	}
	return nil
}

func getResourceVPC(r VPCResourceIntf) (VPCResourceIntf, error) {
	var rVPC VPCResourceIntf
	switch r1Obj := r.(type) {
	case Node:
		rVPC = r1Obj.VPC()
	case NodeSet:
		rVPC = r1Obj.VPC()
	default:
		return nil, errors.New("unexpected resource type to get VPC, should be Node/NodeSet")
	}
	return rVPC, nil
}

// shouldConsiderPairForConnectivity gets a pair of resources from connectivity analysis (r1, r2),
// and returns true if this pair should be considered.
// pairs are discarded when both r1,r2 are the same, or when analysis if cross-vpc connectivity,
// and both r1,r2 are from the same vpc
// the types of r1,r2 should be the same - either both are a Node or a NodeSet
func (c *VPCConfig) shouldConsiderPairForConnectivity(r1, r2 VPCResourceIntf) (bool, error) {
	if r1.UID() == r2.UID() {
		return false, nil
	}
	if c.IsMultipleVPCsConfig {
		r1VPC, err1 := getResourceVPC(r1)
		if err1 != nil {
			return false, err1
		}
		r2VPC, err2 := getResourceVPC(r2)
		if err2 != nil {
			return false, err2
		}
		return r1VPC.UID() != r2VPC.UID(), nil
	}
	return true, nil
}
