package vpcmodel

import (
	"fmt"
	"github.com/np-guard/models/pkg/ipblocks"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const noValidInputMsg = "does not represent an internal interface, an internal IP with network interface or " +
	"a valid external IP"

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

//
// getVPCConfigAndSrcDstNodes given src, dst names returns the config in which the exaplainability analysis of these
// should be done and the Nodes for src and dst
// If src/dst are found in more than one config then configs should agree on their internal/external property
// If src/dst is internal and is found in more than one VCPConfig then in all configs it must have the same VPC()
// If one of src and dst are is internal and the other external then they both must reside in exactly one vpcConfig with
// IsMultipleVPCsConfig = false - which is the returned config
// If both src and dst are internal then only one config may contain both of them - which is the returned config
// if any of the above fails to hold then an error message is returned
// in addition, the following errors, if detected in one of the configs, are relevant in the multiVPC context
// both src and dst are external; src or dst are not unique in a config; src or dst contains both external and internal addr;
// src or dst are within subnets range but not connected to a VSI
// if internalNotWithinSubnet holds for one vpcConfig and there is no match in any of the configs then
// this error is returned

// todo: insert vpc context into error msgs, update test
// todo: check error messages. Reactivate error messages tests
// ToDo: at the moment executing the first match. Add consistency checks and execute on the correct match
func (c VpcsConfigsMap) getVPCConfigAndSrcDstNodes(src, dst string) (vpcConfig *VPCConfig,
	srcNodes, dstNodes []Node, isSrcInternalIP, isDstInternalIP bool, err error) {
	var errMsgInternalNotWithinSubnet, errMsgNoValidInput error
	for i := range c {
		if c[i].IsMultipleVPCsConfig {
			return
		} // todo: tmp until we add support in tgw
		var errType int
		srcNodes, dstNodes, isSrcInternalIP, isDstInternalIP, err, errType = c[i].srcDstInputToNodes(src, dst)
		if err != nil {
			switch errType {
			case exitNowErr:
				return c[i], nil, nil, false, false, err
			case internalNotWithinSubnetsAddr:
				errMsgInternalNotWithinSubnet = err
			case noValidInputErr:
				if srcNodes == nil {
					errMsgNoValidInput = fmt.Errorf("src %s %s", src, err.Error())
				} else { // dstNodes == nil
					errMsgNoValidInput = fmt.Errorf("dst %s %s", src, err.Error())
				}

			}
		}
		if srcNodes != nil && dstNodes != nil { // todo: tmp. needs to add consistency check and choose the correct vpcConfig
			return c[i], srcNodes, dstNodes, isSrcInternalIP, isDstInternalIP, nil
		}
		if errType == internalNotWithinSubnetsAddr {
			errMsgInternalNotWithinSubnet = err
		}
	}
	if errMsgInternalNotWithinSubnet != nil { // this err holds for one vpcConfig and no other match then err is returned
		err = errMsgInternalNotWithinSubnet
	} else {
		err = errMsgNoValidInput
	}
	return nil, nil, nil, false, false, err
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
	isSrcInternalIP, isDstInternalIP bool, err error, errType int) {
	srcNodes, isSrcInternalIP, err, errType = c.getSrcOrDstInputNode(srcName, "src")
	if err != nil {
		return nil, nil, false, false, err, errType
	}
	dstNodes, isDstInternalIP, err, errType = c.getSrcOrDstInputNode(dstName, "dst")
	if err != nil {
		return nil, nil, false, false, err, errType
	}
	// only one of src/dst can be external; there could be multiple nodes only if external
	if !srcNodes[0].IsInternal() && !dstNodes[0].IsInternal() {
		return nil, nil, false, false,
			fmt.Errorf("both src %v and dst %v are external", srcName, dstName), exitNowErr
	}
	return srcNodes, dstNodes, isSrcInternalIP, isDstInternalIP, nil, noErr
}

func (c *VPCConfig) getSrcOrDstInputNode(name, srcOrDst string) (nodes []Node,
	internalIP bool, err error, errType int) {
	outNodes, isInternalIP, err, errType1 := c.getNodesFromInputString(name)
	if err != nil {
		return nil, false, fmt.Errorf("illegal %v: %v", srcOrDst, err.Error()), errType1
	}
	if len(outNodes) == 0 {
		return nil, false, fmt.Errorf(noValidInputMsg), noValidInputErr
	}
	return outNodes, isInternalIP, nil, noErr
}

// given a string cidrOrName representing a vsi or internal/external cidr/address returns the
// corresponding node(s) and a bool which is true iff cidrOrName is an internal address
// (and the nodes are its network interfaces)
func (c *VPCConfig) getNodesFromInputString(cidrOrName string) (nodes []Node, internalIP bool,
	err error, errType int) {
	// 1. cidrOrName references vsi
	vsi, err1, errType1 := c.getNodesOfVsi(cidrOrName)
	if err1 != nil {
		return nil, false, err1, errType1
	}
	if vsi != nil {
		return vsi, false, nil, noErr
	}
	// cidrOrName, if legal, references an address.
	// 2. cidrOrName references an ip address
	ipBlock, err2 := ipblocks.NewIPBlockFromCidrOrAddress(cidrOrName)
	if err2 != nil {
		// the input is not a legal cidr or IP address, which in this stage means it is not a
		// valid presentation for src/dst. Lint demands that an error is returned here
		return nil, false, fmt.Errorf(noValidInputMsg), noValidInputErr
	}
	// the input is a legal cidr or IP address
	return c.getNodesFromAddress(cidrOrName, ipBlock)
}

// getNodesOfVsi gets a string name or UID of VSI, and
// returns the list of all nodes within this vsi
func (c *VPCConfig) getNodesOfVsi(vsi string) ([]Node, error, int) {
	var nodeSetWithVsi NodeSet
	for _, nodeSet := range c.NodeSets {
		// currently assuming c.NodeSets consists of VSIs or VPE
		if nodeSet.Name() == vsi || nodeSet.UID() == vsi {
			if nodeSetWithVsi != nil {
				return nil, fmt.Errorf("in %s there is more than one resource (%s, %s) with the given input string %s representing its name. "+
					"can not determine which resource to analyze. consider using unique names or use input UID instead",
					c.VPC.Name(), nodeSetWithVsi.UID(), nodeSet.UID(), vsi), exitNowErr
			}
			nodeSetWithVsi = nodeSet
		}
	}
	if nodeSetWithVsi == nil {
		return nil, nil, noErr
	}
	return nodeSetWithVsi.Nodes(), nil, noErr
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
	internalIP bool, err error, errType int) {
	// 1.
	_, publicInternet, err1 := getPublicInternetIPblocksList()
	if err1 != nil { // should never get here. If still gets here - severe error, quit with err msg
		return nil, false, err1, exitNowErr
	}
	isExternal := !inputIPBlock.Intersection(publicInternet).Empty()
	isInternal := !inputIPBlock.ContainedIn(publicInternet)
	if isInternal && isExternal {
		return nil, false, fmt.Errorf("%s contains both external and internal addresses which is not supported. "+
			"src, dst should be external *or* internal address", ipOrCidr), exitNowErr
	}
	// 2.
	if isExternal {
		nodes, err, errType = c.getCidrExternalNodes(inputIPBlock)
		if err1 != nil { // should never get here. If still gets here - severe error, quit with err msg
			return nil, false, err, exitNowErr
		} else {
			return nodes, false, nil, noErr
		}
		// internal address
	} else if isInternal {
		// 3.
		vpcAP := c.VPC.AddressRange()
		if !inputIPBlock.ContainedIn(vpcAP) {
			return nil, false, fmt.Errorf("internal address %s not within the vpc %s subnets' address range %s",
				inputIPBlock.ToIPRanges(), c.VPC.Name(), vpcAP.ToIPRanges()), internalNotWithinSubnetsAddr
		}
		// 4.
		networkInterfaces := c.getNodesWithinInternalAddress(inputIPBlock)
		// a given internal address within subnets' addr should have vsi connected to it
		if len(networkInterfaces) == 0 {
			return nil, true,
				fmt.Errorf("no network interfaces are connected to %s in %s", ipOrCidr, c.VPC.Name()), exitNowErr
		}
		return networkInterfaces, true, nil, noErr
	}
	return nil, false, nil, noErr
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
func (c *VPCConfig) getCidrExternalNodes(inputIPBlock *ipblocks.IPBlock) (cidrNodes []Node, err error, errType int) {
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
				return nil, err1, exitNowErr // Should never get here. If still does - severe bug, exit with err
			}
			cidrNodes = append(cidrNodes, node)
		}
	}
	return cidrNodes, nil, noErr
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
