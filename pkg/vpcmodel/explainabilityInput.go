package vpcmodel

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/ipblocks"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type ExplanationArgs struct {
	src        string
	dst        string
	protocol   string
	srcMinPort int64
	srcMaxPort int64
	dstMinPort int64
	dstMaxPort int64
}

func (e *ExplanationArgs) Src() string {
	return e.src
}

func (e *ExplanationArgs) Dst() string {
	return e.dst
}

const (
	noErr                        = iota
	exitNowErr                   // exit now with the error (do not wait until we go over all vpcs)
	internalNotWithinSubnetsAddr // internal address with not within vpc config's subnet addr - wait until we go over all vpcs
	noValidInputErr              // string does not represent a valid input w.r.t. this config - wait as above
)

const (
	noInternalIP        = iota // nor src neither dst were given as internal IP
	srcInternalIP              // only src was given as internal ip
	dstInternalIP              // only dst was given as internal ip
	srcAndDstInternalIP        // both src and dst given as internal ip
)

const noValidInputMsg = "does not represent an internal interface, an internal IP with network interface or " +
	"a valid external IP"

//
// getVPCConfigAndSrcDstNodes given src, dst names returns the config in which the exaplainability analysis of these
// should be done and the Nodes for src and dst.
// At most one config should contain src and dst:
// If one (src or dst) is internal and the other is external or both are internal of the same VPC then the containing VPC
// is the VPC relevant to the explainanility analysis
// todo If src is of one VPC and dst of another, the multiVPC VPCConfig containing both of them is the relevant for explainability,
//      if one exists. Otherwise there is no connection

func (configsMap VpcsConfigsMap) getVPCConfigAndSrcDstNodes(src, dst string) (vpcConfig *VPCConfig,
	srcNodes, dstNodes []Node, isSrcDstInternalIP int, err error) {
	var errMsgInternalNotWithinSubnet, errMsgNoValidInput error
	type srcAndDstNodes struct {
		srcNodes           []Node
		dstNodes           []Node
		isSrcDstInternalIP int
	}
	configsWithSrcDstNode := map[string]srcAndDstNodes{}
	for i := range configsMap {
		if configsMap[i].IsMultipleVPCsConfig {
			return
		} // todo: tmp until we add support in tgw
		var errType int
		srcNodes, dstNodes, isSrcDstInternalIP, errType, err = configsMap[i].srcDstInputToNodes(src, dst)
		if err != nil {
			switch errType {
			case exitNowErr:
				return configsMap[i], nil, nil, noInternalIP, err
			case internalNotWithinSubnetsAddr:
				errMsgInternalNotWithinSubnet = err
			case noValidInputErr:
				errMsgNoValidInput = err
			}
		}
		if srcNodes != nil && dstNodes != nil {
			configsWithSrcDstNode[i] = srcAndDstNodes{srcNodes, dstNodes,
				isSrcDstInternalIP}
		}
	}
	if len(configsWithSrcDstNode) == 0 {
		// no match: internalNotWithinSubnetsAddr err has priority over noValidInputErr
		if errMsgInternalNotWithinSubnet != nil {
			err = errMsgInternalNotWithinSubnet
		} else {
			err = errMsgNoValidInput
		}
		return nil, nil, nil, noInternalIP, err
	}
	// single match: return it
	if len(configsWithSrcDstNode) == 1 {
		for i, val := range configsWithSrcDstNode {
			return configsMap[i], val.srcNodes, val.dstNodes, val.isSrcDstInternalIP, nil
		}
	}
	// src and dst found in more than one VPC configs - error
	var matchConfigs []string
	for i := range configsWithSrcDstNode {
		matchConfigs = append(matchConfigs, i)
	}

	return nil, nil, nil, noInternalIP,
		fmt.Errorf(fmt.Sprintf("src: %s and dst: %s found in more than one config: %s",
			src, dst, strings.Join(matchConfigs, ",")))
}

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
// 1. VSI by UID or name; in this case we consider the network interfaces of the VSI
// 2. Internal IP address or cidr; in this case we consider the vsis in that address range
// 3. external IP address or cidr
func (c *VPCConfig) srcDstInputToNodes(srcName, dstName string) (srcNodes, dstNodes []Node,
	isSrcDstInternalIP int, errType int, err error) {
	var isSrcInternalIP, isDstInternalIP bool
	srcNodes, isSrcInternalIP, errType, err = c.getSrcOrDstInputNode(srcName, "src")
	if err != nil {
		return nil, nil, noInternalIP, errType, err
	}
	dstNodes, isDstInternalIP, errType, err = c.getSrcOrDstInputNode(dstName, "dst")
	if err != nil {
		return nil, nil, noInternalIP, errType, err
	}
	// only one of src/dst can be external; there could be multiple nodes only if external
	if !srcNodes[0].IsInternal() && !dstNodes[0].IsInternal() {
		return nil, nil, noInternalIP, exitNowErr,
			fmt.Errorf("both src %v and dst %v are external", srcName, dstName)
	}
	switch {
	case isSrcInternalIP && isDstInternalIP:
		isSrcDstInternalIP = srcAndDstInternalIP
	case isSrcInternalIP:
		isSrcDstInternalIP = srcInternalIP
	case isDstInternalIP:
		isSrcDstInternalIP = dstInternalIP
	default:
		isSrcDstInternalIP = noInternalIP
	}
	return srcNodes, dstNodes, isSrcDstInternalIP, noErr, nil
}

func (c *VPCConfig) getSrcOrDstInputNode(name, srcOrDst string) (nodes []Node,
	internalIP bool, errType int, err error) {
	outNodes, isInternalIP, errType1, err1 := c.getNodesFromInputString(name)
	if err1 != nil {
		return nil, false, errType1, fmt.Errorf("illegal %v: %v", srcOrDst, err1.Error())
	}
	if len(outNodes) == 0 {
		return nil, false, noValidInputErr, fmt.Errorf(noValidInputMsg)
	}
	return outNodes, isInternalIP, noErr, nil
}

// given a string cidrOrName representing a vsi or internal/external cidr/address returns the
// corresponding node(s) and a bool which is true iff cidrOrName is an internal address
// (and the nodes are its network interfaces)
func (c *VPCConfig) getNodesFromInputString(cidrOrName string) (nodes []Node, internalIP bool,
	errType int, err error) {
	// 1. cidrOrName references vsi
	vsi, errType1, err1 := c.getNodesOfVsi(cidrOrName)
	if err1 != nil {
		return nil, false, errType1, err1
	}
	if vsi != nil {
		return vsi, false, noErr, nil
	}
	// cidrOrName, if legal, references an address.
	// 2. cidrOrName references an ip address
	ipBlock, err2 := ipblocks.NewIPBlockFromCidrOrAddress(cidrOrName)
	if err2 != nil {
		// the input is not a legal cidr or IP address, which in this stage means it is not a
		// valid presentation for src/dst. Lint demands that an error is returned here
		return nil, false, noValidInputErr, fmt.Errorf(noValidInputMsg)
	}
	// the input is a legal cidr or IP address
	return c.getNodesFromAddress(cidrOrName, ipBlock)
}

// getNodesOfVsi gets a string name or UID of VSI, and
// returns the list of all nodes within this vsi
func (c *VPCConfig) getNodesOfVsi(vsi string) ([]Node, int, error) {
	var nodeSetWithVsi NodeSet
	for _, nodeSet := range c.NodeSets {
		// currently assuming c.NodeSets consists of VSIs or VPE
		if nodeSet.Name() == vsi || nodeSet.UID() == vsi {
			if nodeSetWithVsi != nil {
				return nil, exitNowErr, fmt.Errorf("in %s there is more than one resource (%s, %s) with the given input string %s. "+
					"can not determine which resource to analyze. consider using unique names or use input UID instead",
					c.VPC.Name(), nodeSetWithVsi.UID(), nodeSet.UID(), vsi)
			}
			nodeSetWithVsi = nodeSet
		}
	}
	if nodeSetWithVsi == nil {
		return nil, noErr, nil
	}
	return nodeSetWithVsi.Nodes(), noErr, nil
}

// getNodesFromAddress gets a string and IPBlock that represents a cidr or IP address
// and returns the corresponding node(s)and a bool which is true iff ipOrCidr is an internal address
// // (and the nodes are its network interfaces). Specifically:
//  1. If it represents a cidr which is both internal and external, returns an error
//  2. If it presents an external address, returns external addresses nodes and false
//  3. If it contains internal address not within the address range of the vpc's, subnets,
//     returns an error
//  4. If it presents an internal address, return connected network interfaces if any and true,
//  5. If none of the above holds, return nil
//
// todo: 4 - replace subnet's address range in vpc's address prefix
func (c *VPCConfig) getNodesFromAddress(ipOrCidr string, inputIPBlock *ipblocks.IPBlock) (nodes []Node,
	internalIP bool, errType int, err error) {
	// 1.
	_, publicInternet, err1 := getPublicInternetIPblocksList()
	if err1 != nil { // should never get here. If still gets here - severe error, quit with err msg
		return nil, false, exitNowErr, err1
	}
	isExternal := !inputIPBlock.Intersection(publicInternet).Empty()
	isInternal := !inputIPBlock.ContainedIn(publicInternet)
	if isInternal && isExternal {
		return nil, false, exitNowErr,
			fmt.Errorf("%s contains both external and internal addresses which is not supported. "+
				"src, dst should be external *or* internal address", ipOrCidr)
	}
	// 2.
	if isExternal {
		nodes, errType, err = c.getCidrExternalNodes(inputIPBlock)
		if err1 != nil { // should never get here.
			return nil, false, errType, err
		}
		return nodes, false, noErr, nil

		// internal address
	} else if isInternal {
		// 3.
		vpcAP := c.VPC.AddressRange()
		if !inputIPBlock.ContainedIn(vpcAP) {
			return nil, false, internalNotWithinSubnetsAddr,
				fmt.Errorf("internal address %s not within the vpc %s subnets' address range %s",
					inputIPBlock.ToIPRanges(), c.VPC.Name(), vpcAP.ToIPRanges())
		}
		// 4.
		networkInterfaces := c.getNodesWithinInternalAddress(inputIPBlock)
		// a given internal address within subnets' addr should have vsi connected to it
		if len(networkInterfaces) == 0 {
			return nil, true, exitNowErr,
				fmt.Errorf("no network interfaces are connected to %s in %s", ipOrCidr, c.VPC.Name())
		}
		return networkInterfaces, true, noErr, nil
	}
	return nil, false, noErr, nil
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
func (c *VPCConfig) getCidrExternalNodes(inputIPBlock *ipblocks.IPBlock) (cidrNodes []Node, errType int, err error) {
	// 1.
	vpcConfigNodesExternalBlock := []*ipblocks.IPBlock{}
	for _, node := range c.Nodes {
		if node.IsInternal() {
			continue
		}
		vpcConfigNodesExternalBlock = append(vpcConfigNodesExternalBlock, node.IPBlock())
	}
	// 2.
	disjointBlocks := ipblocks.DisjointIPBlocks([]*ipblocks.IPBlock{inputIPBlock}, vpcConfigNodesExternalBlock)
	// 3.
	cidrNodes = []Node{}
	for _, block := range disjointBlocks {
		if block.ContainedIn(inputIPBlock) {
			node, err1 := newExternalNode(true, block)
			if err1 != nil {
				return nil, exitNowErr, err1 // Should never get here. If still does - severe bug, exit with err
			}
			cidrNodes = append(cidrNodes, node)
		}
	}
	return cidrNodes, noErr, nil
}

// getNodesWithinInternalAddress gets input IPBlock
// and returns the list of all internal nodes (should be VSI) within address
func (c *VPCConfig) getNodesWithinInternalAddress(inputIPBlock *ipblocks.IPBlock) (networkInterfaceNodes []Node) {
	networkInterfaceNodes = []Node{}
	for _, node := range c.Nodes {
		if node.IsInternal() && node.IPBlock().ContainedIn(inputIPBlock) {
			networkInterfaceNodes = append(networkInterfaceNodes, node)
		}
	}
	return networkInterfaceNodes
}
