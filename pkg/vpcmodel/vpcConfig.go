package vpcmodel

import (
	"fmt"

	"errors"

	"github.com/np-guard/models/pkg/connection"
)

// VPCConfig captures the configured resources for a VPC
type VPCConfig struct {
	// VPC is a reference to the relevant VPC object for which this config belongs
	VPC VPC
	// Subnets is a list of subnets in the VPC
	Subnets []Subnet
	// LoadBalancers is a list of loadBalancers in the VPC
	LoadBalancers []LoadBalancer
	// Nodes is the list of endpoints in the VPC, such as network interfaces, reserved IPs
	// TODO: also separate Nodes to internal and external nodes lists
	Nodes []Node
	// NodeSets is the list of resources that capture multiple nodes (such as VSIs), and are not of a
	// more specific types that embed NodeSet (such as Subnet/VPC)
	NodeSets []NodeSet
	// FilterResources is the list of resources that define filtering traffic rules, such as ACL, SG
	FilterResources []FilterTrafficResource
	// RoutingResources is the list of resources that enable certain types of connectivity, such as PGW, FIP
	RoutingResources []RoutingResource
	// UIDToResource is a map from resource UID to its object in the VPC
	UIDToResource map[string]VPCResourceIntf
	CloudName     string

	// IsMultipleVPCsConfig is a bool indicator, when set true, it means that the VPCConfig contains resources from
	// multiple VPCs connected to each other, and such config is relevant for reasoning about cross-vpc connectivity
	IsMultipleVPCsConfig bool
}

func (c *VPCConfig) SubnetCidrToSubnetElem(cidr string) (Subnet, error) {
	for _, subnet := range c.Subnets {
		if subnet.CIDR() == cidr {
			return subnet, nil
		}
	}
	return nil, fmt.Errorf("could not find subnet with CIDR %s in VPC %s", cidr, c.VPC.Name())
}

func (c *VPCConfig) getFilterTrafficResourceOfKind(kind string) FilterTrafficResource {
	for _, filter := range c.FilterResources {
		if filter.Kind() == kind {
			return filter
		}
	}
	return nil
}

// shouldConsiderPairForConnectivity gets a pair of resources from connectivity analysis (r1, r2),
// and returns true if this pair should be considered.
// pairs are discarded when both r1,r2 are the same, or when analysis is cross-vpc connectivity,
// and both r1,r2 are from the same vpc
// the types of r1,r2 should be the same - either both are a Node or a NodeSet
func (c *VPCConfig) shouldConsiderPairForConnectivity(r1, r2 VPCResourceIntf) (bool, error) {
	if r1.UID() == r2.UID() {
		return false, nil
	}
	if c.IsMultipleVPCsConfig {
		r1VPC := r1.VPC()
		r2VPC := r2.VPC()
		if r1 == nil || r2 == nil {
			return false, errors.New("error getting VPC of a VPCResourceIntf object")
		}
		return r1VPC.UID() != r2VPC.UID(), nil
	}
	return true, nil
}

// getRoutingResource: gets the routing resource and its conn; currently the conn is either all or none
// node is associated with either a pgw or a fip;
// if the relevant network interface has both the parser will keep only the fip.
func (c *VPCConfig) getRoutingResource(src, dst Node) (RoutingResource, *connection.Set, error) {
	for _, router := range c.RoutingResources {
		routerConnRes, err := router.AllowedConnectivity(src, dst)
		if err != nil {
			return nil, nil, err
		}
		if !routerConnRes.IsEmpty() { // connection is allowed through router resource
			return router, routerConnRes, nil
		}
	}
	return nil, NoConns(), nil
}
