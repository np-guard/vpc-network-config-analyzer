package vpcmodel

import (
	"fmt"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const noValidInputErr = "does not represent a VSI, an internal interface, an internal IP with network interface or " +
	"a valid external IP"

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

// given src and dst input finds the []nodes they represent
// src/dst may refer to:
// 1. NetworkInterface by name
// 2. VSI by UID or name; in this case we consider the network interfaces of the VSI
// 3. Internal IP address; in this case we consider the vsis in that address range
// 4. external IP address
func (c *VPCConfig) srcDstInputToNodes(srcName, dstName string) (srcNodes, dstNodes []Node, err error) {
	srcNodes, err = c.getSrcOrDstInputNode(srcName, "src")
	if err != nil {
		return nil, nil, err
	}
	dstNodes, err = c.getSrcOrDstInputNode(dstName, "dst")
	if err != nil {
		return nil, nil, err
	}
	// only one of src/dst can be external; there could be multiple nodes only if external
	if !srcNodes[0].IsInternal() && !dstNodes[0].IsInternal() {
		return nil, nil, fmt.Errorf("both src %v and dst %v are external", srcName, dstName)
	}
	return srcNodes, dstNodes, nil
}

func (c *VPCConfig) getSrcOrDstInputNode(name, srcOrDst string) ([]Node, error) {
	outNodes, err := c.getNodesFromInputString(name)
	if err != nil {
		return nil, fmt.Errorf("illegal %v: %v", srcOrDst, err.Error())
	}
	if len(outNodes) == 0 {
		return nil, fmt.Errorf(fmt.Sprintf("%v %v %v", srcOrDst, name, noValidInputErr))
	}
	return outNodes, nil
}

// given a string or a vsi or a cidr returns the corresponding node(s)
func (c *VPCConfig) getNodesFromInputString(cidrOrName string) ([]Node, error) {
	// 1. cidrOrName references a network interface
	if networkInterfaces := c.getNetworkInterfaceNodes(cidrOrName); len(networkInterfaces) > 0 {
		return networkInterfaces, nil
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
	// 3. cidrOrName references an ip address
	return c.getNodesFromAddress(cidrOrName)
}

// finds nodes of a given, by its name, NetworkInterface (if any)
func (c *VPCConfig) getNetworkInterfaceNodes(name string) []Node {
	networkInterfaceNodes := []Node{}
	for _, node := range c.Nodes {
		if name == node.Name() {
			networkInterfaceNodes = append(networkInterfaceNodes, node)
		}
	}
	return networkInterfaceNodes
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
	if nodeSetWithVsi == nil {
		return nil, nil
	}
	return nodeSetWithVsi.Nodes(), nil
}

// getNodesFromAddress gets a string that should present a cidr or IP
// 1. If it does not present a cidr or IP, returns nil
// 2. If it represents a cidr which is both internal and external, returns an error
// 3. If it presents an external address, returns external addresses nodes
// 4. If it presents an internal address, return connected network interfaces if any, error otherwise
func (c *VPCConfig) getNodesFromAddress(ipOrCidr string) ([]Node, error) {
	inputIPBlock := common.NewIPBlockFromCidrOrAddress(ipOrCidr)
	if inputIPBlock == nil { // 1. string cidr does not represent a legal cidr
		return nil, nil
	}
	// 2.
	_, publicInternet, err1 := getPublicInternetIPblocksList()
	if err1 != nil {
		return nil, err1
	}
	isExternal := !inputIPBlock.Intersection(publicInternet).Empty()
	isInternal := !inputIPBlock.ContainedIn(publicInternet)
	if isInternal && isExternal {
		return nil, fmt.Errorf(fmt.Sprintf("%s contains external and internal addresses which is not supported. "+
			"src, dst should be external *or* internal address", ipOrCidr))
	}
	if isExternal { // 3.
		return c.getCidrExternalNodes(inputIPBlock)
	} else if isInternal { // 4.
		networkInterfaces, err2 := c.getNodesWithinInternalAddress(inputIPBlock)
		if err2 != nil {
			return nil, err2
		}
		// a given internal address should have vsi connected to it
		if networkInterfaces == nil {
			return nil, fmt.Errorf(fmt.Sprintf("No network interfaces are connected to %s", ipOrCidr))
		}
		return networkInterfaces, nil
	}
	return nil, nil
}

// given input IPBlock, gets (disjoint) external nodes I s.t.:
//  1. The union of these nodes is the cidr
//  2. Let i be a node in I and n be a node in VPCConfig.
//     i and n are either disjoint or i is contained in n
//     Note that the vpconfig nodes were chosen w.r.t. connectivity rules (SG and NACL)
//     s.t. each node either fully belongs to a rule or is disjoint to it.
//     to get nodes I as above:
//  1. Calculate the IP blocks of the nodes N
//  2. Calculate from N and the cidr block, disjoint IP blocks
//  3. Return the nodes created from each block from 2 contained in the input cidr
func (c *VPCConfig) getCidrExternalNodes(inputIPBlock *common.IPBlock) (cidrNodes []Node, err error) {
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
	disjointBlocks := common.DisjointIPBlocks([]*common.IPBlock{inputIPBlock}, vpcConfigNodesExternalBlock)
	// 3.
	cidrNodes = []Node{}
	for _, block := range disjointBlocks {
		if block.ContainedIn(inputIPBlock) {
			node, err1 := newExternalNode(true, block)
			if err1 != nil {
				return nil, err1
			}
			cidrNodes = append(cidrNodes, node)
		}
	}
	return cidrNodes, nil
}

// getNodesWithinInternalAddress gets input IPBlock
// and returns the list of all internal nodes (should be VSI) within address
func (c *VPCConfig) getNodesWithinInternalAddress(inputIPBlock *common.IPBlock) (networkInterfaceNodes []Node, err error) {
	var networkInterfaceIPBlock *common.IPBlock
	networkInterfaceNodes = []Node{}
	for _, node := range c.Nodes {
		if networkInterfaceIPBlock, err = common.NewIPBlockFromIPAddress(node.Cidr()); err != nil {
			return nil, err
		}
		contained := networkInterfaceIPBlock.ContainedIn(inputIPBlock)
		if node.IsExternal() && contained {
			return nil, fmt.Errorf("src or dst address %s represents an external IP", inputIPBlock)
		}
		if node.IsInternal() && contained {
			networkInterfaceNodes = append(networkInterfaceNodes, node)
		}
	}
	return networkInterfaceNodes, nil
}
