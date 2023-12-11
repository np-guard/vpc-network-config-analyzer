package vpcmodel

import (
	"fmt"
)

// stage 1: vsi to vsi of the same subnet (Adi prefers the definition "vsi to vsi considering only SGs")
//          this is relatively simple since only SG can effect this connection, and SG has only enabling rules

// stage 1:
// input: src and dst, both vsi names in string
// 1. Translate src and dst to Nodes
//    if there is a connection:
// 2. Find the ingress and egress rules enabling the connection in the SGAnalyzer struct.
//    specifically, the []*SGRule ingressRules and egressRules contributing to the connection.
//    There are two alternatives of achieving this:
//    a) adding the following functionality:
//      func (sg *SecurityGroup) ConnOfSGRules(src, dst vpcmodel.Node, isIngress bool) []*SGRule/[]uniqueIdsOfSGRules
//      whose functionality is similar to that of
//              func (sg *SecurityGroup) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *common.ConnectionSet
//      and for the most part based on the same code
//    In this case after ParseResourcesFromFile and VPCConfigsFromResources dedicated analysis based on ConnOfSGRules will be performed,
//    and the general connectivity analysis functionality will not be called
//
//    b) Enhancing the structure
//        type ConnectivityResult struct {
//       by adding to it the list of the rules contributing to the connection []*SGRule/[]uniqueIdsOfSGRules
//    In this case in addition to ParseResourcesFromFile and VPCConfigsFromResources, GetVPCNetworkConnectivity will be called
//     after which a dedicated function for collecting the relevant SG rules will be deployed.
//
//   Alternative a) chosen
//
//  3. Extract the actual sg rules from *SGRule and print as output.
//
//     if there is no connection:
// 2' .Find which connection is missing: ingress, egress or both
//     If the missing connection is ingress: is it the default?
//
//
//     * pointer to the original rule has to be added to SGRule struct [perhaps the first PR here]

// finds the node of a given, by its name, Vsi
func (c *VPCConfig) getVsiNode(name string) Node {
	for _, node := range c.Nodes {
		// currently, supported: network interface given takes only that one.
		//  todo:   if address not given but only vsi name - take all network interfaces of that vsi
		if name == node.Name() {
			return node
		}
	}
	return nil
}

func (c *VPCConfig) ExplainConnectivity(srcName, dstName string) error {
	src := c.getVsiNode(srcName)
	if src == nil {
		return fmt.Errorf("src %v does not represent a VSI", srcName)
	}
	dst := c.getVsiNode(dstName)
	if dst == nil {
		return fmt.Errorf("dst %v does not represent a VSI", srcName)
	}
	// todo tmp
	fmt.Printf("Explanbility for connection between %s to %s\n", src.Name(), dst.Name())
	// todo in this stage only SG considered, thus only
	//      connectivity between nodes of the same subnet is supported
	// ingress rules
	ingressRules, err1 := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, true, SecurityGroupLayer)
	if err1 != nil {
		return err1
	}
	// egress rules
	egressRules, err2 := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, true, SecurityGroupLayer)
	if err2 != nil {
		return err2
	}
	switch {
	case ingressRules == nil && egressRules == nil:
		fmt.Printf("No connection between %v and %v; connection blocked both by ingress and egress\n", src.Name(), dst.Name())
	case ingressRules == nil:
		fmt.Printf("No connection between %v and %v; connection blocked by ingress\n", src.Name(), dst.Name())
	case egressRules == nil:
		fmt.Printf("No connection between %v and %v; connection blocked by egress\n", src.Name(), dst.Name())
	}
	return nil
}

func (c *VPCConfig) getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(
	src, dst Node,
	isIngress bool,
	layer string) ([]int, error) {
	filter := c.getFilterTrafficResourceOfKind(layer)
	if filter == nil {
		return nil, nil
	}
	return filter.RulesInConnectivity(src, dst, isIngress)
}
