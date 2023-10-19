package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"

	"errors"
	"fmt"
)

type SubnetConnectivityMap map[EndpointElem]map[EndpointElem]*common.ConnectionSet

// VPCsubnetConnectivity captures allowed connectivity for subnets, considering nacl and pgw resources
type VPCsubnetConnectivity struct {
	// computed for each node (subnet), by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[EndpointElem]*ConfigBasedConnectivityResults
	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined SubnetConnectivityMap
	CloudConfig          *CloudConfig
	// grouped connectivity result
	GroupedConnectivity *GroupConnLines
}

const (
	subnetKind                = "Subnet"
	pgwKind                   = "PublicGateway"
	errUnexpectedTypePeerNode = "unexpected type for peerNode in computeAllowedConnsCombined"
)

func NewSubnetConnectivityMap() SubnetConnectivityMap {
	return SubnetConnectivityMap{}
}

func subnetConnLine(subnet string, conn *common.ConnectionSet) string {
	return fmt.Sprintf("%s : %s\n", subnet, conn.String())
}

func (c *ConfigBasedConnectivityResults) string() string {
	res := "Ingress: \n"
	for n, conn := range c.IngressAllowedConns {
		res += subnetConnLine(n.Name(), conn)
	}
	res += "Egress: \n"
	for n, conn := range c.EgressAllowedConns {
		res += subnetConnLine(n.Name(), conn)
	}

	return res
}

var _ = (*VPCsubnetConnectivity).printAllowedConns // avoiding "unused" warning

// print AllowedConns (not combined)
func (v *VPCsubnetConnectivity) printAllowedConns() {
	for n, connMap := range v.AllowedConns {
		fmt.Println(n.Name())
		fmt.Println(connMap.string())
		fmt.Println("-----------------")
	}
}

func (c *CloudConfig) ipblockToNamedResourcesInConfig(ipb *common.IPBlock, excludeExternalNodes bool) ([]VPCResourceIntf, error) {
	res := []VPCResourceIntf{}

	// consider subnets
	for _, nodeset := range c.NodeSets {
		if nodeset.Kind() != subnetKind {
			continue
		}
		var subnetCidrIPB *common.IPBlock
		if subnetCidrIPB = nodeset.AddressRange(); subnetCidrIPB == nil {
			return nil, errors.New("missing AddressRange for subnet")
		}
		if subnetCidrIPB.ContainedIn(ipb) {
			res = append(res, nodeset)
		}
	}

	if excludeExternalNodes {
		return res, nil
	}

	// consider external nodes
	for _, exn := range c.Nodes {
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

func (c *CloudConfig) convertIPbasedToSubnetBasedResult(ipconn *IPbasedConnectivityResult, hasPGW bool) (
	*ConfigBasedConnectivityResults,
	error,
) {
	res := NewConfigBasedConnectivityResults()

	for ipb, conn := range ipconn.IngressAllowedConns {
		// PGW does not allow ingress traffic but the ingress is required for the stateful computation
		if namedResources, err := c.ipblockToNamedResourcesInConfig(ipb, !hasPGW); err == nil {
			for _, n := range namedResources {
				res.IngressAllowedConns[n] = conn
			}
		} else {
			return nil, err
		}
	}

	// egress traffic to external nodes may be enabled by a public gateway
	for ipb, conn := range ipconn.EgressAllowedConns {
		if namedResources, err := c.ipblockToNamedResourcesInConfig(ipb, !hasPGW); err == nil {
			for _, n := range namedResources {
				res.EgressAllowedConns[n] = conn
			}
		} else {
			return nil, err
		}
	}
	return res, nil
}

func (c *CloudConfig) subnetCidrToSubnetElem(cidr string) (NodeSet, error) {
	cidrIPBlock := common.NewIPBlockFromCidr(cidr)
	elems, err := c.ipblockToNamedResourcesInConfig(cidrIPBlock, true)
	if err != nil {
		return nil, err
	}
	err = errors.New("unexpected res for IPblockToNamedResourcesInConfig on input subnet cidr")
	if len(elems) != 1 {
		return nil, err
	}
	if nodeSetElem, ok := elems[0].(NodeSet); ok {
		if nodeSetElem.Kind() != subnetKind {
			return nil, err
		}
		return nodeSetElem, nil
	}
	return nil, err
}

// the main function to compute connectivity per subnet based on resources that capture subnets, such as nacl, pgw, routing-tables
func (c *CloudConfig) GetSubnetsConnectivity(includePGW, grouping bool) (*VPCsubnetConnectivity, error) {
	var subnetsConnectivityFromACLresources map[string]*IPbasedConnectivityResult
	var err error
	for _, fl := range c.FilterResources {
		if fl.Kind() == NaclLayer {
			subnetsConnectivityFromACLresources, err = fl.ConnectivityMap()
			if err != nil {
				return nil, err
			}
		}
	}
	if subnetsConnectivityFromACLresources == nil {
		return nil, errors.New("missing connectivity results from NACL resources")
	}

	subnetsWithPGW := map[string]bool{}
	for _, r := range c.RoutingResources {
		if r.Kind() == pgwKind {
			conns := r.ConnectivityMap()
			for subnetCidr := range conns {
				subnetsWithPGW[subnetCidr] = true
			}
		}
	}

	// convert to subnet-based connectivity result
	subnetsConnectivity := map[EndpointElem]*ConfigBasedConnectivityResults{}
	for subnetCidrStr, ipBasedConnectivity := range subnetsConnectivityFromACLresources {
		subnetNodeSet, err := c.subnetCidrToSubnetElem(subnetCidrStr)
		if err != nil {
			return nil, err
		}

		// create and update configBasedConns according to relevant router (pgw) resources
		subnetHasPGW := false
		if subnetsWithPGW[subnetCidrStr] {
			subnetHasPGW = true
		}
		if !includePGW {
			subnetHasPGW = true // do not limit connectivity to external nodes only if has actual PGW
		}
		configBasedConns, err := c.convertIPbasedToSubnetBasedResult(ipBasedConnectivity, subnetHasPGW)
		if err != nil {
			return nil, err
		}

		subnetsConnectivity[subnetNodeSet] = configBasedConns
	}

	res := &VPCsubnetConnectivity{AllowedConns: subnetsConnectivity, CloudConfig: c}

	// get combined connections from subnetsConnectivity
	if err := res.computeAllowedConnsCombined(); err != nil {
		return nil, err
	}
	res.computeStatefulConnections()

	res.GroupedConnectivity = newGroupConnLinesSubnetConnectivity(c, res, grouping)

	return res, nil
}

func (v *VPCsubnetConnectivity) computeAllowedConnsCombined() error {
	v.AllowedConnsCombined = map[EndpointElem]map[EndpointElem]*common.ConnectionSet{}
	for subnetNodeSet, connsRes := range v.AllowedConns {
		for peerNode, conns := range connsRes.IngressAllowedConns {
			src := peerNode
			dst := subnetNodeSet
			if src.Name() == dst.Name() {
				continue
			}

			var combinedConns *common.ConnectionSet
			// peerNode kind is expected to be Subnet or External
			peerNodeObj := v.CloudConfig.NameToResource[peerNode.Name()]
			switch concPeerNode := peerNodeObj.(type) {
			case NodeSet:
				egressConns := v.AllowedConns[concPeerNode].EgressAllowedConns[subnetNodeSet]
				combinedConns = conns.Intersection(egressConns)
			case *ExternalNetwork:
				// PGW does not allow ingress traffic
			default:
				return errors.New(errUnexpectedTypePeerNode)
			}
			if combinedConns == nil {
				continue
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[EndpointElem]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
		for peerNode, conns := range connsRes.EgressAllowedConns {
			src := subnetNodeSet
			dst := peerNode
			if src.Name() == dst.Name() {
				continue
			}
			combinedConns := conns

			// peerNode kind is expected to be Subnet or External
			peerNodeObj := v.CloudConfig.NameToResource[peerNode.Name()]
			switch peerNodeObj.(type) {
			case NodeSet:
				continue
			case *ExternalNetwork:
				// do nothing
			default:
				return errors.New(errUnexpectedTypePeerNode)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[EndpointElem]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
	}
	return nil
}

func (v *VPCsubnetConnectivity) computeStatefulConnections() {
	for src, endpointConns := range v.AllowedConnsCombined {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			dstObj := v.CloudConfig.NameToResource[dst.Name()]
			var otherDirectionConn *common.ConnectionSet
			switch dstObj.(type) {
			case NodeSet:
				otherDirectionConn = v.AllowedConnsCombined[dst][src]
			case *ExternalNetwork:
				// subnet to external node is stateful if the subnet's nacl allows ingress from that node.
				// This connection will *not* be considered by AllowedConnsCombined since ingress connection
				// from external nodes can not be initiated for pgw
				otherDirectionConn = v.AllowedConns[src].IngressAllowedConns[dst]
			default:
			}
			conns.IsStateful = common.StatefulFalse
			if otherDirectionConn == nil {
				continue
			}
			connsSwitchPortsDirection := conns.ResponseConnection()
			stateful := connsSwitchPortsDirection.Intersection(otherDirectionConn)
			// if there is a way back for the response, then the connection is considered stateful
			if !stateful.IsEmpty() {
				conns.IsStateful = common.StatefulTrue
			}
		}
	}
}

func (v *VPCsubnetConnectivity) String() string {
	res := "combined connections between subnets:\n"
	// res += v.GroupedConnectivity.String() ToDo: uncomment once https://github.com/np-guard/vpc-network-config-analyzer/issues/138 is solved
	res += v.GroupedConnectivity.String()
	return res
}

// GetConnectivityOutputPerEachSubnetSeparately returns string results of connectivity analysis per
// single subnet with its attached nacl, separately per subnet - useful to get understanding of the
// connectivity implied from nacl configuration applied on a certain subnet in the vpc
func (c *CloudConfig) GetConnectivityOutputPerEachSubnetSeparately() string {
	// iterate over all subnets, collect all outputs per subnet connectivity
	for _, r := range c.FilterResources {
		if r.Kind() == NaclLayer {
			return r.GetConnectivityOutputPerEachElemSeparately()
		}
	}
	return ""
}

func (connectivity SubnetConnectivityMap) updateAllowedSubnetConnsMap(src, dst NodeSet, conn *common.ConnectionSet) {
	if _, ok := connectivity[src]; !ok {
		connectivity[src] = map[EndpointElem]*common.ConnectionSet{}
	}
	connectivity[src][dst] = conn
}
