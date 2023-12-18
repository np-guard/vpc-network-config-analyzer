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

// ExplainConnectivity todo: this will not be needed here once we connect explanbility to the cli
func (c *VPCConfig) ExplainConnectivity(srcName, dstName string) (explanation string, err error) {
	src := c.getVsiNode(srcName)
	if src == nil {
		return "", fmt.Errorf("src %v does not represent a VSI", srcName)
	}
	dst := c.getVsiNode(dstName)
	if dst == nil {
		return "", fmt.Errorf("dst %v does not represent a VSI", dstName)
	}
	rulesOfConnection, err1 := c.GetRulesOfConnection(src, dst)
	if err1 != nil {
		return "", err1
	}
	return rulesOfConnection.String(src, dst, c)
}

func (c *VPCConfig) getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(
	src, dst Node, isIngress bool, layer string) *[]RulesInFilter {
	filter := c.getFilterTrafficResourceOfKind(layer)
	if filter == nil {
		return nil
	}
	rulesOfFilter, err := filter.RulesInConnectivity(src, dst, isIngress)
	if err != nil {
		return nil
	}
	return &rulesOfFilter
}

func (c *VPCConfig) GetRulesOfConnection(src, dst Node) (rulesOfConnection *RulesOfConnection, err error) {
	filterLayers := []string{SecurityGroupLayer}
	rulesOfConnection = &RulesOfConnection{make([]rulesInLayer, len(filterLayers)),
		make([]rulesInLayer, len(filterLayers))}
	for i, layer := range filterLayers {
		// ingress rules
		ingressRules := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, true, layer)
		ingressThisLayer := rulesInLayer{layer: layer, rules: *ingressRules}
		rulesOfConnection.ingressRules[i] = ingressThisLayer

		// egress rules
		egressRules := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, false, layer)
		if len(*egressRules) > 0 {
			egressThisLayer := rulesInLayer{layer: layer, rules: *egressRules}
			rulesOfConnection.egressRules[i] = egressThisLayer
		}
	}
	return rulesOfConnection, nil
}

func (rulesOfConnection *RulesOfConnection) String(src, dst Node, c *VPCConfig) (string, error) {
	noIngressRules := !rulesOfConnection.ingressRules.hasRules()
	noEgressRules := !rulesOfConnection.egressRules.hasRules()
	switch {
	case noIngressRules && noEgressRules:
		return fmt.Sprintf("No connection between %v and %v; connection blocked both by ingress and egress\n", src.Name(), dst.Name()), nil
	case noIngressRules:
		return fmt.Sprintf("No connection between %v and %v; connection blocked by ingress\n", src.Name(), dst.Name()), nil
	case noEgressRules:
		return fmt.Sprintf("No connection between %v and %v; connection blocked by egress\n", src.Name(), dst.Name()), nil
	default: // there is a connection
		// todo: connectivity is computed for the entire network, even though we need only src-> dst
		//       this is seems the time spent here should be neglectable, not worth the effort of adding dedicated code.
		connectivity, err := c.GetVPCNetworkConnectivity(false) // computes connectivity
		if err != nil {
			return "", err
		}
		conn, ok := connectivity.AllowedConnsCombined[src][dst]
		if !ok {
			return "", fmt.Errorf("error: there is a connection between %v and %v, but connection computation failed",
				src.Name(), dst.Name())
		}
		egressRulesStr := rulesOfConnection.egressRules.string(c)
		ingressRulesStr := rulesOfConnection.ingressRules.string(c)
		return fmt.Sprintf("The following connection exists between %v and %v: %v; its enabled by\nEgress Rules:\n~~~~~~~~~~~~~\n%v\n"+
			"Ingress Rules:\n~~~~~~~~~~~~~~\n%v\n", src.Name(), dst.Name(), conn.String(), egressRulesStr, ingressRulesStr), nil
	}
}

func (rulesInLayers *rulesInLayers) hasRules() bool {
	if rulesInLayers == nil {
		return false
	}
	for _, rulesInLayer := range *rulesInLayers {
		if len(rulesInLayer.rules) > 0 {
			return true
		}
	}
	return false
}

func (rulesInLayers *rulesInLayers) string(c *VPCConfig) string {
	rulesInLayersStr := ""
	for _, rulesInLayer := range *rulesInLayers {
		filter := c.getFilterTrafficResourceOfKind(rulesInLayer.layer)
		if filter == nil {
			continue
		}
		rulesInLayersStr += rulesInLayer.layer + " Rules\n------------------------\n" +
			filter.StringRulesOfFilter(rulesInLayer.rules)
	}
	return rulesInLayersStr
}
