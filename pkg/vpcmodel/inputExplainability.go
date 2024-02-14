package vpcmodel

import (
	"fmt"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const noValidInputErr = "%v does not represent a VSI, an internal interface or a valid external or internal IP"

// GetConnectionSet TODO: handle also input ICMP properties (type, code) as input args
// translates explanation args to a connection set
func (e *ExplanationArgs) GetConnectionSet() *common.ConnectionSet {
	if e.protocol == "" {
		return nil
	}
	connection := common.NewConnectionSet(false)
	if common.ProtocolStr(e.protocol) == common.ProtocolICMP {
		connection.AddICMPConnection(common.MinICMPtype, common.MaxICMPtype,
			common.MinICMPcode, common.MaxICMPcode)
	} else {
		connection.AddTCPorUDPConn(common.ProtocolStr(e.protocol), e.srcMinPort,
			e.srcMaxPort, e.dstMinPort, e.dstMaxPort)
	}

	return connection
}

// todo: temp dump after calling the srcDstInputToNodes; integrate Ola's function; update error messages;
//       error message for external + internal address together

// given src and dst input finds the []nodes they represent
// src/dst may refer to:
// 1. NetworkInterface by name
// 2. VSI by UID or name; in this case we consider all the network interfaces of the VSI
// 3. Internal IP address
func (c *VPCConfig) srcDstInputToNodes(srcName, dstName string) (srcNodes, dstNodes []Node, err error) {
	srcNodes, err = c.getNodesFromInputString(srcName)
	if err != nil {
		return nil, nil, err
	}
	if len(srcNodes) == 0 {
		return nil, nil, fmt.Errorf("src %v %v", noValidInputErr, srcName)
	}
	dstNodes, err = c.getNodesFromInputString(dstName)
	if err != nil {
		return nil, nil, err
	}
	if len(dstNodes) == 0 {
		return nil, nil, fmt.Errorf("dst %v %v", noValidInputErr, dstName)
	}
	// only one of src/dst can be external; there could be multiple nodes only if external
	if !srcNodes[0].IsInternal() && !dstNodes[0].IsInternal() {
		return nil, nil, fmt.Errorf("both src %v and dst %v are external", srcName, dstName)
	}
	return srcNodes, dstNodes, nil
}

// given a string or a vsi or a cidr returns the corresponding node(s)
func (c *VPCConfig) getNodesFromInputString(cidrOrName string) ([]Node, error) {
	// 1. cidrOrName references a network interface
	if networkInterface := c.getNetworkInterfaceNode(cidrOrName); networkInterface != nil {
		return []Node{networkInterface}, nil
	}
	// 2. cidrOrName references vsi
	vsi, err1 := c.getNodesOfVsi(cidrOrName)
	if err1 != nil {
		return nil, err1
	}
	if vsi != nil {
		return vsi, nil
	}
	// cidrOrName, if legal, references an address.
	// 3. ToDo verifies cidrOrName does not references a combination of internal and external address
	// 4. cidrOrName references external address
	// 5. ToDo cidrOrName references internal address
	return c.getCidrExternalNodes(cidrOrName)
}

// finds the node of a given, by its name, NetworkInterface (if any)
func (c *VPCConfig) getNetworkInterfaceNode(name string) Node {
	for _, node := range c.Nodes {
		// currently, supported: network interface given takes only that one.
		//  todo:   if address not given but only vsi name - take all network interfaces of that vsi
		if name == node.Name() {
			return node
		}
	}
	return nil
}

// getNodesOfVsi gets a string name or UID of VSI, and
// returns the list of all nodes within this vsi
func (c *VPCConfig) getNodesOfVsi(vsi string) ([]Node, error) {
	var nodeSetWithVsi NodeSet
	for _, nodeSet := range c.NodeSets {
		// todo: at the moment we consider here all NodeSets and not just vsis (e.g. also subnets)
		//       fix once we have abstract vpc and subnets (#380)
		if nodeSet.Name() == vsi || nodeSet.UID() == vsi {
			if nodeSetWithVsi != nil {
				return nil, fmt.Errorf("there is more than one resource (%s, %s) with the given input string %s representing its name. "+
					"can not determine which resource to analyze. consider using unique names or use input UID instead",
					nodeSetWithVsi.UID(), nodeSet.UID(), vsi)
			}
			nodeSetWithVsi = nodeSet
		}
	}
	return nodeSetWithVsi.Nodes(), nil
}

// getNodesFromAddress gets a string that should present a cidr or IP
// 1. If it does not present a cidr or IP, return nil
// 2. Verifies it presents either an external or an internal address; otherwise return an error
// 3. If it presents an external address, returns external addresses nodes
// 4. If it presents internal address, return connected network interfaces if any, error otherwise
func (c *VPCConfig) getNodesFromAddress(ipOrCidr string) ([]Node, error) {
	cidrsIPBlock := common.NewIPBlockFromCidrOrAddress(ipOrCidr)
	if cidrsIPBlock == nil { // 1. string cidr does not represent a legal cidr
		return nil, nil
	}
	// 2.
	isExternal, isInternal := false, false

	if isExternal && isInternal {
		return nil, fmt.Errorf(fmt.Sprintf("%s contains external and internal addresses which is not supported. "+
			"src, dst should be external *or* internal address", ipOrCidr))
	}
	if isExternal {
		return c.getCidrExternalNodes(ipOrCidr)
	}
	return nil, nil
}

// given input cidr, gets (disjoint) external nodes I s.t.:
//  1. The union of these nodes is the cidr
//  2. Let i be a node in I and n be a node in VPCConfig.
//     i and n are either disjoint or i is contained in n
//     Note that the vpconfig nodes were chosen w.r.t. connectivity rules (SG and NACL)
//     s.t. each node either fully belongs to a rule or is disjoint to it.
//     to get nodes I as above:
//  1. Calculate the IP blocks of the nodes N
//  2. Calculate from N and the cidr block, disjoint IP blocks
//  3. Return the nodes created from each block from 2 contained in the input cidr
func (c *VPCConfig) getCidrExternalNodes(ipOrCidr string) (cidrNodes []Node, err error) {
	cidrsIPBlock := common.NewIPBlockFromCidrOrAddress(ipOrCidr)
	if cidrsIPBlock == nil { // string cidr does not represent a legal cidr
		return nil, nil
	}
	// 1.
	vpcConfigNodesExternalBlock := []*common.IPBlock{}
	for _, node := range c.Nodes {
		if node.IsInternal() {
			continue
		}
		thisNodeBlock := common.NewIPBlockFromCidr(node.Cidr())
		vpcConfigNodesExternalBlock = append(vpcConfigNodesExternalBlock, thisNodeBlock)
	}
	// 2.
	disjointBlocks := common.DisjointIPBlocks([]*common.IPBlock{cidrsIPBlock}, vpcConfigNodesExternalBlock)
	// 3.
	cidrNodes = []Node{}
	for _, block := range disjointBlocks {
		if block.ContainedIn(cidrsIPBlock) {
			node, err1 := newExternalNode(true, block)
			if err1 != nil {
				return nil, err1
			}
			cidrNodes = append(cidrNodes, node)
		}
	}
	return cidrNodes, nil
}

// getNodesWithinInternalAddress gets a string address in CIDR format or exact IP address format representing internal address
// and returns the list of all internal nodes (should be VSI) within address
func (c *VPCConfig) getNodesWithinInternalAddress(ipOrCidr string) (networkInterfaceNodes []Node, err error) {
	var addressIPblock, networkInterfaceIPBlock *common.IPBlock
	addressIPblock = common.NewIPBlockFromCidrOrAddress(ipOrCidr)

	networkInterfaceNodes = []Node{}
	for _, node := range c.Nodes {
		if networkInterfaceIPBlock, err = common.NewIPBlockFromIPAddress(node.Cidr()); err != nil {
			return nil, err
		}
		contained := networkInterfaceIPBlock.ContainedIn(addressIPblock)
		if node.IsExternal() && contained {
			return nil, fmt.Errorf("src or dst address %s represents an external IP", ipOrCidr)
		}
		if node.IsInternal() && contained {
			networkInterfaceNodes = append(networkInterfaceNodes, node)
		}
	}
	return networkInterfaceNodes, nil
}
