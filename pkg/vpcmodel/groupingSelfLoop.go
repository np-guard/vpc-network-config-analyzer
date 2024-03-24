package vpcmodel

import (
	"strings"
)

// extends grouping by considering self loops as don't care https://github.com/np-guard/vpc-network-config-analyzer/issues/98
// e.g. a => b,c   b => a, c   and   c => a,b   is actually a clique a,b,c => a,b,c
// a => b,c, b => c can be presented in one line as  a,b => b,c

// After the basic grouping, which is of worst time complexity O(n^2), we optimize grouping treating self loops as don't care.
// Intuitively, we check if two GroupedConnLine can be merged treating self loops as don't care
// 1. groupsToBeMerged find couples of GroupedConnLine that should be merged using the alg below
// mergeSelfLoops merges the groupsToBeMerged:
// 2. It creates sets of GroupedConnLine s.t. each set should be merged
//			note that the "should be merged" is an equivalence relation
// 3. It merges them

// alg: GroupedConnLine to be merged:
// GroupedConnLine whose distance is an empty set should be merged;
// the claim below guarantees that the result is coherent
//
// The distance between two GroupedConnLine is defined as following:
// Let l_1 be a line with source s_1 and dest d_1 and let l_2 be a line with source s_2 and dest d_2.
// l_1 / l_2 is the vsis/subnets in d_1 that are not in d_2 minus the single vsi/subnet in s_1 if |s_1| = 1
//
// The distance between lines l_1 and l_2 is l_1 / l_2 union l_2 / l_1
//
// claim: if the distance between line l_1 and l_2 is an empty set and
//		 the distance between lines l_2 and l_3 is an empty set
//		 then so is the distance between l_1 and l_3

// main function. Input: <current grouping, grouping src or dst>
// output: grouping after treating self loops as don't care
func (g *GroupConnLines) extendGroupingSelfLoops(groupingSrcOrDst map[string][]*groupedConnLine,
	srcGrouping bool) map[string][]*groupedConnLine {
	toMergeCouples := g.groupsToBeMerged(groupingSrcOrDst, srcGrouping)
	return mergeSelfLoops(toMergeCouples, groupingSrcOrDst, srcGrouping)
}

// detects couples of groups that can be merged when self loops are treated as don't cares
// Input: <current grouping, grouping src or dst>
// Output: couples of groups that can be merged. Each couple is presented as a couple of strings where each string is the
// key of the group from the map of the current grouping
func (g *GroupConnLines) groupsToBeMerged(groupingSrcOrDst map[string][]*groupedConnLine, srcGrouping bool) (toMergeCouples [][2]string) {
	toMergeCouples = make([][2]string, 0)
	// the to be grouped src/dst in set representation, will be needed to compute potential groups to be merged
	// and to compute the deltas
	setsToGroup := createGroupingSets(groupingSrcOrDst, srcGrouping)
	relevantKeys := g.relevantKeysToCompare(groupingSrcOrDst)
	keyToMergeCandidates := g.findMergeCandidates(groupingSrcOrDst, srcGrouping, setsToGroup, relevantKeys)

	for _, key := range relevantKeys {
		keyLines := groupingSrcOrDst[key]
		//  is there a different line s.t. the keyLines were not merged only due to self loops?
		// 	going over all couples of items: merging them if they differ only in self loop element
		// findMergeCandidates of a singleton 'key' are all lines in which the group contains 'key'
		//  if key is not a singleton then findMergeCandidates will be empty
		mergeCandidates, ok := keyToMergeCandidates[key]
		if !ok {
			continue
		}
		for candidate := range mergeCandidates {
			candidateLines := groupingSrcOrDst[candidate]
			// delta between keyLines to candidateLines must be 0
			mergeGroups := isDeltaOfGroupedLinesZero(srcGrouping, keyLines, candidateLines, setsToGroup[key], setsToGroup[candidate])
			// delta between the keyLines is 0 - merge keyLines
			if mergeGroups {
				toMergeCouples = append(toMergeCouples, [2]string{key, candidate})
			}
		}
	}
	return toMergeCouples
}

// gets a list of keys of groups that have the potential of being merged with the
// self loop don't care optimization
// a group is candidate to be merged only if it has only internal nodes
// if vsis then of the same subnet
// and if subnets then of the same vpc
// the latter follows from the 3rd condition described in findMergeCandidates
// Input: <current grouping, grouping src or dst>
// Output: <list of keys>
func (g *GroupConnLines) relevantKeysToCompare(groupingSrcOrDst map[string][]*groupedConnLine) (relevantKeys []string) {
	relevantKeys = make([]string, 0, len(groupingSrcOrDst))
	for key, lines := range groupingSrcOrDst {
		if lines[0].isSrcOrDstExternalNodes() {
			continue
		}
		// if vsi then the subnets must be equal; if not vsis then empty string equals empty string
		if getSubnetUIDIfVsi(lines[0].src) != getSubnetUIDIfVsi(lines[0].dst) {
			continue
		}
		// if subnets then the vpc must be equal; if not subnets then empty string equals empty string
		if getVPCUIDIfSubnet(lines[0].src) != getVPCUIDIfSubnet(lines[0].dst) {
			continue
		}
		relevantKeys = append(relevantKeys, key)
	}
	return
}

// optimization to reduce the worst case of finding couples to merge from O(n^4) to O(n^2)
// where n is the number of nodes.
// a couple of []*GroupedConnLine is candidate to be merged only if:
//  1. They are of the same connection
//  2. If vsis, of the same subnet
//  3. The src (dst) in one group is a singleton contained in the dst (src) in the other
//     in one pass on groupingSrcOrDst we prepare a map between each key to the keys that are candidates to be merged with it.
//     Before the grouping there are at most O(n^2) lines of src -> dst
//     The last condition implies that each original src -> dst (where src and dst are a single endpoint) can induce a single
//     candidate (at most), and each singleton key have at most n candidates. Hence, there are at most
//     O(n^3) merge candidate, which implies O(n^3) time complexity of groupsToBeMerged
//
// Input: <current grouping, grouping src or dst, set representation of groups, list of relevant keys>
// Output: <couples to be merged>
func (g *GroupConnLines) findMergeCandidates(groupingSrcOrDst map[string][]*groupedConnLine, srcGrouping bool,
	keyToGroupedSets map[string]map[string]struct{}, relevantKeys []string) map[string]map[string]struct{} {
	// 1. Create buckets for each connection + vsi's subnet if vsi; merge candidates are within each bucket
	bucketToKeys := make(map[string]map[string]struct{})
	for _, key := range relevantKeys {
		lines := groupingSrcOrDst[key]
		bucket := lines[0].commonProperties.groupingStrKey
		subnetIfVsiVPCIfSubnet := getSubnetUIDIfVsi(lines[0].src)
		if subnetIfVsiVPCIfSubnet == "" {
			subnetIfVsiVPCIfSubnet = getVPCUIDIfSubnet(lines[0].src)
		}
		if subnetIfVsiVPCIfSubnet != "" {
			bucket += semicolon + subnetIfVsiVPCIfSubnet
		}
		if _, ok := bucketToKeys[bucket]; !ok {
			bucketToKeys[bucket] = make(map[string]struct{})
		}
		bucketToKeys[bucket][key] = struct{}{}
	}

	keyToMergeCandidates := make(map[string]map[string]struct{})
	// 2. in each bucket finds for each key the candidates to be merged, in two stages
	for _, keysInBucket := range bucketToKeys {
		singletonsInBucket := make(map[string]string)
		//    2.1 for a group g_1 s.t. the non-grouped src/dst is a singleton,
		//        all groups in which the grouped dst/src contains the singleton
		//        2.1.1 finds for each bucket all singletons
		for key := range keysInBucket {
			lines := groupingSrcOrDst[key]
			elemsInKey := elemInKeys(!srcGrouping, *lines[0])
			if len(elemsInKey) > 1 { // not a singleton
				continue
			}
			singleton := elemsInKey[0]
			singletonsInBucket[singleton] = key
		}
		//   2.1.2 finds for each singleton candidates: groups with that singleton
		//    stores the candidates in keyToMergeCandidates
		for key := range keysInBucket {
			itemsInGroup := keyToGroupedSets[key]
			for item := range itemsInGroup {
				if mergeCandidateKey, ok := singletonsInBucket[item]; ok {
					if mergeCandidateKey != key {
						if _, ok := keyToMergeCandidates[mergeCandidateKey]; !ok {
							keyToMergeCandidates[mergeCandidateKey] = make(map[string]struct{})
						}
						if _, ok := keyToMergeCandidates[key]; !ok {
							keyToMergeCandidates[key] = make(map[string]struct{})
						}
						keyToMergeCandidates[mergeCandidateKey][key] = struct{}{}
					}
				}
			}
		}
	}
	return keyToMergeCandidates
}

// if ep is a vsi or a group of vsis, gets its subnet
// (if its a group of vsis then they all have the same subnet by grouping rules)
func getSubnetUIDIfVsi(ep EndpointElem) string {
	if isVsi, node := isEpVsi(ep); isVsi {
		// if ep is groupedEndpointsElems of vsis then all belong to the same subnet
		return node.Subnet().UID()
	}
	return ""
}

// input: Endpoint
// output: <bool, node>:
// if the endpoint element represents a vsi or is a slice of elements the first of which represents vsi
// then it returns <true, the vsi or the first vsi>
// otherwise it returns <false, nil>
func isEpVsi(ep EndpointElem) (bool, InternalNodeIntf) {
	if _, ok := ep.(*groupedEndpointsElems); ok {
		ep1GroupedEps := ep.(*groupedEndpointsElems)
		if node, ok := (*ep1GroupedEps)[0].(Node); ok {
			if node.IsInternal() {
				return true, node.(InternalNodeIntf)
			}
		}
		return false, nil
	}
	if node, ok := ep.(Node); ok {
		if node.IsInternal() {
			return true, node.(InternalNodeIntf)
		}
	}
	return false, nil
}

// if ep is a subnet or a group of subnets, gets its vpc
// (if its a group of subnets then they all have the same vpc by grouping rule)
func getVPCUIDIfSubnet(ep EndpointElem) string {
	if isSubnet, nodeSet := isEpSubnet(ep); isSubnet {
		// if ep is groupedEndpointsElems of vsis then all belong to the same subnet
		return nodeSet.VPC().UID()
	}
	return ""
}

// input: Endpoint
// output: <bool, node>:
// if the endpoint element represents a subnet or is a slice of elements the first of which represents subnet
// then it returns <true, the subnet or the first subnet>
// otherwise it returns <false, nil>
func isEpSubnet(ep EndpointElem) (bool, NodeSet) {
	if _, ok := ep.(*groupedEndpointsElems); ok {
		ep1GroupedEps := ep.(*groupedEndpointsElems)
		if nodeSet, ok := (*ep1GroupedEps)[0].(NodeSet); ok {
			return true, nodeSet
		}
		return false, nil
	}
	if nodeSet, ok := ep.(NodeSet); ok {
		return true, nodeSet
	}
	return false, nil
}

// creates an aux database in which all the grouped endpoints are stored in a set
// Input: <current grouping, grouping src or dst>
// Output: <for each group a set of its endpoints names>
func createGroupingSets(groupingSrcOrDst map[string][]*groupedConnLine, srcGrouping bool) map[string]map[string]struct{} {
	keyToGroupedSets := make(map[string]map[string]struct{})
	for key, groupedConnLine := range groupingSrcOrDst {
		mySet := make(map[string]struct{})
		for _, line := range groupedConnLine {
			srcOrDst := line.getSrcOrDst(srcGrouping)
			mySet[srcOrDst.Name()] = struct{}{}
		}
		keyToGroupedSets[key] = mySet
	}
	return keyToGroupedSets
}

// computes delta between group connection lines as defined in the beginning of the file
// Input: <grouping src or dst, groupedConnLine to compute delta between, sets representation of the groups>
// Output: true if the delta is zero, false otherwise
func isDeltaOfGroupedLinesZero(srcGrouping bool, groupedConnLine1, groupedConnLine2 []*groupedConnLine,
	setToGroup1, setToGroup2 map[string]struct{}) bool {
	// at least one of the keys must be a single vsi/subnet for the self loop check to be meaningful
	if len(elemInKeys(srcGrouping, *groupedConnLine1[0])) > 1 && len(elemInKeys(srcGrouping, *groupedConnLine2[0])) > 1 {
		return false
	}
	// is there is a real delta between sets and not only due to self loop
	set1MinusSet2 := setMinusSet(srcGrouping, *groupedConnLine2[0], setToGroup1, setToGroup2)
	set2MinusSet1 := setMinusSet(srcGrouping, *groupedConnLine1[0], setToGroup2, setToGroup1)
	if len(set1MinusSet2) == 0 && len(set2MinusSet1) == 0 {
		return true
	}
	return false
}

// given a GroupedConnLine returns a list of the names of the endpoint elements
// in its key
func elemInKeys(srcGrouping bool, groupedLine groupedConnLine) []string {
	srcOrDst := groupedLine.getSrcOrDst(srcGrouping)
	return strings.Split(srcOrDst.Name(), commaSeparator)
}

// computes the distance  between two GroupedConnLine as defined in the beginning of the file
// Input: <grouping src or dst, groupedConnLine to compute delta between, sets representation of the groups>
// Output: the distance between the groups
func setMinusSet(srcGrouping bool, groupedLine groupedConnLine, set1, set2 map[string]struct{}) map[string]struct{} {
	minusResult := make(map[string]struct{})
	for k := range set1 {
		if _, ok := set2[k]; !ok {
			minusResult[k] = struct{}{}
		}
	}
	// if set2's groupedConnLine key has a single item, then this single item is not relevant to the delta
	// since any EndpointElement is connected to itself
	if len(elemInKeys(srcGrouping, groupedLine)) == 1 {
		keyOfGrouped2 := groupedLine.getSrcOrDst(!srcGrouping) // all non-grouping items are the same in a groupedConnLine
		delete(minusResult, keyOfGrouped2.Name())              // if keyOfGrouped2.Name() does not exist in minusResult then this is no-op
	}
	return minusResult
}

func (g *groupedConnLine) isSrcOrDstExternalNodes() bool {
	if _, ok := g.src.(*groupedExternalNodes); ok {
		return true
	}
	if _, ok := g.dst.(*groupedExternalNodes); ok {
		return true
	}
	return false
}

// actual merge of groupedConnLine that should be merged
// input: <list of groupedConnLine to be merged, current grouping, grouping src or dst>
// output: <new grouping>
func mergeSelfLoops(toMergeCouples [][2]string, oldGroupingSrcOrDst map[string][]*groupedConnLine,
	srcGrouping bool) map[string][]*groupedConnLine {
	// 1. Create dedicated data structure: a slice of slices of string toMergeList s.t. each slice contains a list of keys to be merged
	//    and a map toMergeExistingIndexes between key to its index in the slice
	toMergeList := make([][]string, 0)
	toMergeExistingIndexes := make(map[string]int)
	for _, coupleKeys := range toMergeCouples {
		existingIndx1, ok1 := toMergeExistingIndexes[coupleKeys[0]]
		existingIndx2, ok2 := toMergeExistingIndexes[coupleKeys[1]]
		switch ok1 {
		case true:
			if !ok2 {
				toMergeExistingIndexes[coupleKeys[1]] = existingIndx1
				toMergeList[existingIndx1] = append(toMergeList[existingIndx1], coupleKeys[1])
			}
		case false:
			if ok2 {
				toMergeExistingIndexes[coupleKeys[0]] = existingIndx2
				toMergeList[existingIndx2] = append(toMergeList[existingIndx2], coupleKeys[0])
			} else {
				// if both []*GroupedConnLine already exist in toMergeExistingIndexes then
				//    existingIndx1 equals existingIndx2 and nothing to be done here
				nextIndx := len(toMergeList)
				toMergeExistingIndexes[coupleKeys[0]], toMergeExistingIndexes[coupleKeys[1]] = nextIndx, nextIndx
				newList := []string{coupleKeys[0], coupleKeys[1]}
				toMergeList = append(toMergeList, newList)
			}
		}
	}
	// 2. Performs the actual merge
	//    Build New map[string][]*GroupedConnLine :
	mergedGroupedConnLine := make(map[string][]*groupedConnLine)
	//    2.1 go over the new data structure, merge groups to be merged and add to New
	//    2.2 go over old map[string][]*GroupedConnLine and for each element whose key not in toMergeKeys then just add it as is
	for _, toBeMergedKeys := range toMergeList {
		newKey, newGroupedConnLines := mergeGivenList(oldGroupingSrcOrDst, srcGrouping, toBeMergedKeys)
		mergedGroupedConnLine[newKey] = newGroupedConnLines
	}
	for oldKey, oldLines := range oldGroupingSrcOrDst {
		// not merged with other groups, add as is
		if _, ok := toMergeExistingIndexes[oldKey]; !ok {
			if _, existInNewKeys := mergedGroupedConnLine[oldKey]; existInNewKeys {
				mergedGroupedConnLine[oldKey] = append(mergedGroupedConnLine[oldKey], oldLines...)
			} else {
				mergedGroupedConnLine[oldKey] = oldLines
			}
		}
	}
	return mergedGroupedConnLine
}

// given a list of keys to be merged from the old grouping, computes unique list of endpoints
// of either sources or destination as by srcGrouping
// returns the unique list of endpoints and the connection
// input: <old grouping, grouping src or dst, list of key to be merged>
// output: <list of endpoints, their connection>
func listOfUniqueEndpoints(oldGroupingSrcOrDst map[string][]*groupedConnLine, srcGrouping bool,
	toMergeKeys []string) (listOfEndpoints groupedEndpointsElems, conn string, connProps *groupedCommonProperties) {
	setOfNames := make(map[string]struct{})
	listOfEndpoints = make(groupedEndpointsElems, 0)
	for _, oldKeyToMerge := range toMergeKeys {
		for _, line := range oldGroupingSrcOrDst[oldKeyToMerge] {
			endPointInKey := line.getSrcOrDst(!srcGrouping)
			if conn == "" {
				conn = line.commonProperties.groupingStrKey // connection is the same for all lines to be merged
				connProps = line.commonProperties
			}
			if _, isSliceEndpoints := endPointInKey.(*groupedEndpointsElems); isSliceEndpoints {
				for _, endpoint := range *endPointInKey.(*groupedEndpointsElems) {
					if _, ok := setOfNames[endpoint.Name()]; !ok { // was endpoint added already?
						listOfEndpoints = append(listOfEndpoints, endpoint)
						setOfNames[endpoint.Name()] = struct{}{}
					}
				}
			} else { // endpoint is Node or NodeSet
				if _, ok := setOfNames[endPointInKey.Name()]; !ok { // was endpoint added already?
					listOfEndpoints = append(listOfEndpoints, endPointInKey)
					setOfNames[endPointInKey.Name()] = struct{}{}
				}
			}
		}
	}
	return listOfEndpoints, conn, connProps
}

// merges a list of GroupedConnLine to be merged
// input: <old grouping, grouping src or dst, list of key to be merged>
// output: new key, new []*GroupedConnLine
func mergeGivenList(oldGroupingSrcOrDst map[string][]*groupedConnLine, srcGrouping bool,
	toMergeKeys []string) (newKey string, newGroupedConnLine []*groupedConnLine) {
	epsInNewKey, _, _ := listOfUniqueEndpoints(oldGroupingSrcOrDst, srcGrouping, toMergeKeys)
	epsInNewLines, conn, commonPros := listOfUniqueEndpoints(oldGroupingSrcOrDst, !srcGrouping, toMergeKeys)
	for _, epInLineValue := range epsInNewLines {
		if srcGrouping {
			newGroupedConnLine = append(newGroupedConnLine, &groupedConnLine{epInLineValue, &epsInNewKey, commonPros})
		} else {
			newGroupedConnLine = append(newGroupedConnLine, &groupedConnLine{&epsInNewKey, epInLineValue, commonPros})
		}
	}
	// all grouped items have the same subnets (if vsi) or vpc (if subnets), so any would do for the key
	newKey = getKeyOfGroupConnLines(&epsInNewKey, epsInNewLines[0], conn)
	return
}
