package vpcmodel

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type IPbasedConnectivityResult struct {
	IngressAllowedConns map[*common.IPBlock]*common.ConnectionSet
	EgressAllowedConns  map[*common.IPBlock]*common.ConnectionSet
}

type ConfigBasedConnectivityResults struct {
	IngressAllowedConns map[string]*common.ConnectionSet
	EgressAllowedConns  map[string]*common.ConnectionSet
}

func (c *ConfigBasedConnectivityResults) String() string {
	res := "Ingress: \n"
	for n, conn := range c.IngressAllowedConns {
		res += fmt.Sprintf("%s : %s\n", n, conn.String())
	}
	res += "Egress: \n"
	for n, conn := range c.EgressAllowedConns {
		res += fmt.Sprintf("%s : %s\n", n, conn.String())
	}

	return res
}

// detailed representation of allowed connectivity considering subnet resources and their relevant affecting resources
type VPCsubnetConnectivity struct {
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[string]*ConfigBasedConnectivityResults
	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined map[string]map[string]*common.ConnectionSet
	//nameToNamedResourceIntf map[string]NamedResourceIntf
	//nameToNodeSet           map[string]NodeSet
	cloudConfig *CloudConfig
}

// print AllowedConns (not combined)
func (v VPCsubnetConnectivity) printAllowedConns() {
	for n, connMap := range v.AllowedConns {
		fmt.Println(n)
		fmt.Println(connMap.String())
		fmt.Println("-----------------")
	}
}

func (v *CloudConfig) IPblockToNamedResourcesInConfig(ipb *common.IPBlock, excludeExternalNodes bool) ([]NamedResourceIntf, error) {
	res := []NamedResourceIntf{}

	// consider subnets
	for _, nodeset := range v.NodeSets {
		if nodeset.Kind() != "Subnet" {
			continue
		}
		subnetDetails := nodeset.DetailsMap()
		if subnetCidr, ok := subnetDetails[DetailsAttributeCIDR]; ok {
			subnetCidrIPB := common.NewIPBlockFromCidr(subnetCidr)
			// TODO: consider also connectivity to part of the subnet
			if subnetCidrIPB.ContainedIn(ipb) {
				res = append(res, nodeset)
			}
		} else {
			return nil, errors.New("missing subnet cidr")
		}
	}
	if excludeExternalNodes {
		return res, nil
	}

	// consider external nodes
	for _, exn := range v.Nodes {
		if exn.IsInternal() {
			continue
		}
		nodeCidr := exn.Cidr()
		nodeCidrIPB := common.NewIPBlockFromCidr(nodeCidr)
		if nodeCidrIPB.ContainedIn(ipb) {
			res = append(res, exn)
		}
	}

	return res, nil
}

func (v *CloudConfig) ConvertIPbasedToSubnetBasedResult(ipconn *IPbasedConnectivityResult, hasPGW bool) (*ConfigBasedConnectivityResults, error) {
	res := &ConfigBasedConnectivityResults{
		IngressAllowedConns: map[string]*common.ConnectionSet{},
		EgressAllowedConns:  map[string]*common.ConnectionSet{},
	}

	for ipb, conn := range ipconn.IngressAllowedConns {
		if namedResources, err := v.IPblockToNamedResourcesInConfig(ipb, !hasPGW); err == nil {
			for _, n := range namedResources {
				res.IngressAllowedConns[n.Name()] = conn
			}
		} else {
			return nil, err
		}
	}

	for ipb, conn := range ipconn.EgressAllowedConns {
		if namedResources, err := v.IPblockToNamedResourcesInConfig(ipb, !hasPGW); err == nil {
			for _, n := range namedResources {
				res.EgressAllowedConns[n.Name()] = conn
			}
		} else {
			return nil, err
		}
	}

	return res, nil
}

func (v *CloudConfig) subnetCidrToSubnetElem(cidr string) (NodeSet, error) {
	cidrIPBlock := common.NewIPBlockFromCidr(cidr)
	elems, err := v.IPblockToNamedResourcesInConfig(cidrIPBlock, true)
	if err != nil {
		return nil, err
	}
	err = errors.New("unexpected res for IPblockToNamedResourcesInConfig on input subnet cidr")
	if len(elems) != 1 {
		return nil, err
	}
	if nodeSetElem, ok := elems[0].(NodeSet); ok {
		if nodeSetElem.Kind() != "Subnet" {
			return nil, err
		}
		return nodeSetElem, nil
	}
	return nil, err

}

// connectivity per subnet based on resources that capture subnets, such as nacl, pgw, routing-tables
func (v *CloudConfig) GetSubnetsConnectivity(includePGW bool) (*VPCsubnetConnectivity, error) {
	var subnetsConnectivityFromACLresources map[string]*IPbasedConnectivityResult
	for _, fl := range v.FilterResources {
		if fl.Kind() == "NaclLayer" {
			subnetsConnectivityFromACLresources = fl.ConnectivityMap()
		}
	}
	if subnetsConnectivityFromACLresources == nil {
		return nil, errors.New("missing connectivity results from NACL resources")
	}

	pgwConns := map[string]ConfigBasedConnectivityResults{}
	for _, r := range v.RoutingResources {
		if r.Kind() == "PublicGateway" {
			conns := r.ConnectivityMap()
			for subnetCidr, pgwConnsPerCidr := range conns {
				pgwConns[subnetCidr] = pgwConnsPerCidr
			}
		}
	}

	// convert to subnet-based connectivity result
	subnetsConnectivity := map[string]*ConfigBasedConnectivityResults{}
	for subnetCidrStr, ipBasedConnectivity := range subnetsConnectivityFromACLresources {
		subnetNodeSet, err := v.subnetCidrToSubnetElem(subnetCidrStr)
		if err != nil {
			return nil, err
		}

		// create and update configBasedConns according to relevant router (pgw) resources
		subnetHasPGW := false
		if _, ok := pgwConns[subnetCidrStr]; ok {
			subnetHasPGW = true
		}
		if !includePGW {
			subnetHasPGW = true // do not limit connectivity to external nodes only if has actual PGW
		}
		configBasedConns, err := v.ConvertIPbasedToSubnetBasedResult(ipBasedConnectivity, subnetHasPGW)
		if err != nil {
			return nil, err
		}

		subnetsConnectivity[subnetNodeSet.Name()] = configBasedConns

	}

	res := &VPCsubnetConnectivity{AllowedConns: subnetsConnectivity, cloudConfig: v}

	res.printAllowedConns()
	// get combined connections from subnetsConnectivity
	if err := res.computeAllowedConnsCombined(); err != nil {
		return nil, err
	}

	return res, nil
}

func (v *VPCsubnetConnectivity) computeAllowedConnsCombined() error {
	v.AllowedConnsCombined = map[string]map[string]*common.ConnectionSet{}
	for subnetNodeSet, connsRes := range v.AllowedConns {
		for peerNode, conns := range connsRes.IngressAllowedConns {
			src := peerNode
			dst := subnetNodeSet
			combinedConns := conns.Copy()

			//peerNode kind is expected to be Subnet or External
			peerNodeObj := v.cloudConfig.NameToResource[peerNode]
			switch concPeerNode := peerNodeObj.(type) {
			case NodeSet:
				egressConns := v.AllowedConns[concPeerNode.Name()].EgressAllowedConns[subnetNodeSet]
				combinedConns.Intersection(*egressConns)
			case *ExternalNetwork:
				// do nothing
			default:
				return errors.New("unexpected type for peerNode in computeAllowedConnsCombined")
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[string]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
		for peerNode, conns := range connsRes.EgressAllowedConns {
			src := subnetNodeSet
			dst := peerNode
			combinedConns := conns

			//peerNode kind is expected to be Subnet or External
			peerNodeObj := v.cloudConfig.NameToResource[peerNode]
			switch concPeerNode := peerNodeObj.(type) {
			case NodeSet:
				ingressConns := v.AllowedConns[concPeerNode.Name()].IngressAllowedConns[subnetNodeSet]
				combinedConns.Intersection(*ingressConns)
			case *ExternalNetwork:
				// do nothing
			default:
				return errors.New("unexpected type for peerNode in computeAllowedConnsCombined")
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[string]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
	}

	return nil
}

func (v *VPCsubnetConnectivity) String() string {
	res := "=================================== combined connections - short version:\n"
	strList := []string{}
	for src, nodeConns := range v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			if conns.IsEmpty() {
				continue
			}
			//srcName := src.Name()
			//dstName := dst.Name()
			strList = append(strList, getConnectionStr(src, dst, conns.String(), ""))
		}
	}
	sort.Strings(strList)
	res += strings.Join(strList, "")
	return res
}
