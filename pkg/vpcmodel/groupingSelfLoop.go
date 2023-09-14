package vpcmodel

import (
	"sort"
	"strings"
)

// extends grouping by considering self loops https://github.com/np-guard/vpc-network-config-analyzer/issues/98
func (g *GroupConnLines) extendGroupingSelfLoops(groupingSrcOrDst map[string][]*GroupedConnLine,
	srcGrouping bool) map[string][]*GroupedConnLine {
	toMergeCouples := g.groupsToBeMerged(groupingSrcOrDst, srcGrouping)
	return mergeSelfLoops(toMergeCouples, groupingSrcOrDst, srcGrouping)
}

func (g *GroupConnLines) groupsToBeMerged(groupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool) (toMergeCouples [][2]string) {
	toMergeCouples = make([][2]string, 0)
	// the to be grouped src/dst in set representation, will be needed to compute potential groups to be merged
	// and to compute the deltas
	setsToGroup := createGroupingSets(groupingSrcOrDst, srcGrouping)
	// in order to compare each couple only once, compare only couples in one half of the matrix.
	// To that end we must define an order and travers it - sorted sortedKeys
	sortedKeys := sortedKeysToCompared(groupingSrcOrDst)
	keyToMergeCandidates := g.mergeCandidates(groupingSrcOrDst, srcGrouping, setsToGroup, sortedKeys)

	for _, key := range sortedKeys {
		keyLines := groupingSrcOrDst[key]
		//  is there a different line s.t. the keyLines were not merged only due to self loops?
		// 	going over all couples of items: merging them if they differ only in self loop element
		mergeCandidates, ok := keyToMergeCandidates[key]
		if !ok {
			continue
		}
		for candidate := range mergeCandidates {
			candidateLines := groupingSrcOrDst[candidate]
			// delta between outerKeyEndPointElements to innerKeyEndPointElements must be 0
			mergeGroups := deltaBetweenGroupedConnLines(srcGrouping, keyLines, candidateLines, setsToGroup[key], setsToGroup[candidate])
			// delta between the keyLines is 0 - merge keyLines
			if mergeGroups {
				var toMerge = [2]string{key}
				toMergeCouples = append(toMergeCouples, toMerge)
			}
		}
	}
	return toMergeCouples
}

// a group is candidate to be merged only if it has only internal nodes; sorting keys so that the iteration order will be preserved
func sortedKeysToCompared(groupingSrcOrDst map[string][]*GroupedConnLine) (sortedKeys []string) {
	sortedKeys = make([]string, 0, len(groupingSrcOrDst))
	for key, lines := range groupingSrcOrDst {
		if lines[0].isSrcOrDstExternalNodes() {
			continue
		}
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)
	return
}

// optimization that reduces the worst case time of groupsToBeMerged from (nxn)^2 to (nxn)*n where n is the number
// of vsis or of subnets
// assume w.l.o.g that src are grouped. There is a point in comparing group s1 => d1 to group s2 => d2
// only if both have the same connection and are VSIs/subnets and
// s1 is a singleton and is contained in d2 or vice versa
// optimization to reduce the worst case of finding couples to merge from O(n^4) to O(n^2)
// a couple of []*GroupedConnLine is candidate to be merged only if:
//  1. They are of the same connection
//  2. If vsis, of the same subnet
//  3. The src/dst is a singelton contained in the dst/src
//     in one path on groupingSrcOrDst we prepare a map between each key to the keys that are candidate to be merged with it
//     the last condition implies that each original src -> dst (where src and dst are a single endpoint) can induce a single
//     candidate (at most), and each singelton key have at most n candidates. Hence the O(n^3) of  groupsToBeMerged above
func (g *GroupConnLines) mergeCandidates(groupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool,
	keyToGroupedSets map[string]map[string]struct{}, sortedKeys []string) map[string]map[string]struct{} {
	// 1. Create buckets for each connection + vsi's subnet if vsi; merge candidates are within each bucket
	bucketToKeys := make(map[string]map[string]struct{})
	for _, key := range sortedKeys {
		lines := groupingSrcOrDst[key]
		bucket := lines[0].Conn
		bucket = g.addVsiSubnetToBucket(lines[0].Src, bucket)
		bucket = g.addVsiSubnetToBucket(lines[0].Dst, bucket)
		if _, ok := bucketToKeys[bucket]; !ok {
			bucketToKeys[bucket] = make(map[string]struct{})
		}
		bucketToKeys[bucket][key] = struct{}{}
	}

	keyToMergeCandidates := make(map[string]map[string]struct{})
	// 2. in each bucket finds for each key the candidates to be merged, in two stages
	for _, keysInBucket := range bucketToKeys {
		singeltonsInBucket := make(map[string]string)
		//    2.1 for a group g_1 s.t. the non-grouped src/dst is a singelton,
		//        all groups in which the grouped dst/src contains the singelton
		//        2.1.1 finds for each bucket all singeltons
		for key := range keysInBucket {
			lines := groupingSrcOrDst[key]
			elemsInkey := elemInKeys(!srcGrouping, *lines[0])
			if len(elemsInkey) > 1 { // not a singelton
				continue
			}
			singelton := elemsInkey[0]
			singeltonsInBucket[singelton] = key
		}
		//   2.1.2 finds for each singelton candidates: groups with that singelton
		//    stores the candidates in keyToMergeCandidates
		for key := range keysInBucket {
			itemsInGroup := keyToGroupedSets[key]
			for item := range itemsInGroup {
				if mergeCandidateKey, ok := singeltonsInBucket[item]; ok {
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

func (g *GroupConnLines) addVsiSubnetToBucket(ep EndpointElem, bucket string) string {
	if isVsi, node := isEpVsi(ep); isVsi {
		return bucket + ";" + g.c.getSubnetOfNode(node).Name()
	}
	return bucket
}

// returns true, vsi if the endpoint element represents a vsi or is a slice of elements the first of which represents vsi
// otherwise returns false, nil
func isEpVsi(ep EndpointElem) (bool, Node) {
	if _, ok := ep.(*groupedEndpointsElems); ok {
		ep1GroupedEps := ep.(*groupedEndpointsElems)
		if node, ok := (*ep1GroupedEps)[0].(Node); ok {
			if node.IsInternal() {
				return true, node
			}
		}
		return false, nil
	}
	if node, ok := ep.(Node); ok {
		if node.IsInternal() {
			return true, node
		}
	}
	return false, nil
}

// creates an aux database in which all the grouped endpoints are stored in a set
func createGroupingSets(groupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool) map[string]map[string]struct{} {
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

// computes delta between group connection lines https://github.com/np-guard/vpc-network-config-analyzer/issues/98
func deltaBetweenGroupedConnLines(srcGrouping bool, groupedConnLine1, groupedConnLine2 []*GroupedConnLine,
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

func elemInKeys(srcGrouping bool, groupedConnLine GroupedConnLine) []string {
	srcOrDst := groupedConnLine.getSrcOrDst(srcGrouping)
	return strings.Split(srcOrDst.Name(), commaSepartor)
}

func setMinusSet(srcGrouping bool, groupedConnLine GroupedConnLine, set1, set2 map[string]struct{}) map[string]struct{} {
	minusResult := make(map[string]struct{})
	for k := range set1 {
		if _, ok := set2[k]; !ok {
			minusResult[k] = struct{}{}
		}
	}
	// if set2's groupedConnLine key has a single item, then this single item is not relevant to the delta
	// since any EndpointElement is connected to itself
	if len(elemInKeys(srcGrouping, groupedConnLine)) == 1 {
		keyOfGrouped2 := groupedConnLine.getSrcOrDst(!srcGrouping) // all non-grouping items are the same in a groupedConnLine
		delete(minusResult, keyOfGrouped2.Name())                  // if keyOfGrouped2.Name() does not exist in minusResult then this is no-op
	}
	return minusResult
}

func (g *GroupedConnLine) isSrcOrDstExternalNodes() bool {
	if _, ok := g.Src.(*groupedExternalNodes); ok {
		return true
	}
	if _, ok := g.Dst.(*groupedExternalNodes); ok {
		return true
	}
	return false
}

func mergeSelfLoops(toMergeCouples [][2]string, oldGroupingSrcOrDst map[string][]*GroupedConnLine,
	srcGrouping bool) map[string][]*GroupedConnLine {
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
	mergedGroupedConnLine := make(map[string][]*GroupedConnLine)
	//    2.1 go over the new data structure, merge groups to be merged and add to New
	//    2.2 go over old map[string][]*GroupedConnLine and for each element whose key not in toMergeKeys then just add it as is
	for _, toBeMergedKeys := range toMergeList {
		newKey, newGroupedConnLines := mergeGivenList(oldGroupingSrcOrDst, srcGrouping, toBeMergedKeys)
		mergedGroupedConnLine[newKey] = newGroupedConnLines
	}
	for oldKey, oldLines := range oldGroupingSrcOrDst {
		// not merged with other groups, add as is
		if _, ok := toMergeExistingIndexes[oldKey]; !ok {
			mergedGroupedConnLine[oldKey] = oldLines
		}
	}
	return mergedGroupedConnLine
}

// given a list of keys to be merged from of oldGroupingSrcOrDst, computes unique list of endpoints
// of either sources or destination as by srcGrouping
// returns the unique list of endpoints, their names and the connection
func listOfUniqueEndpoints(oldGroupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool,
	toMergeKeys []string) (listOfEndpoints groupedEndpointsElems, setOfNames map[string]struct{}, conn string) {
	setOfNames = make(map[string]struct{})
	listOfEndpoints = make(groupedEndpointsElems, 0)
	for _, oldKeyToMerge := range toMergeKeys {
		for _, line := range oldGroupingSrcOrDst[oldKeyToMerge] {
			endPointInKey := line.getSrcOrDst(!srcGrouping)
			if conn == "" {
				conn = line.Conn // connection is the same for all lines to be merged
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
	return
}

func mergeGivenList(oldGroupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool,
	toMergeKeys []string) (newKey string, newGroupedConnLine []*GroupedConnLine) {
	epsInNewKey, namesInNewKey, _ := listOfUniqueEndpoints(oldGroupingSrcOrDst, srcGrouping, toMergeKeys)
	epsInNewLines, _, conn := listOfUniqueEndpoints(oldGroupingSrcOrDst, !srcGrouping, toMergeKeys)
	for _, epInLineValue := range epsInNewLines {
		if srcGrouping {
			newGroupedConnLine = append(newGroupedConnLine, &GroupedConnLine{epInLineValue, &epsInNewKey, conn})
		} else {
			newGroupedConnLine = append(newGroupedConnLine, &GroupedConnLine{&epsInNewKey, epInLineValue, conn})
		}
	}
	srcsOrDstsInNewKeySlice := make([]string, 0)
	for item := range namesInNewKey {
		srcsOrDstsInNewKeySlice = append(srcsOrDstsInNewKeySlice, item)
	}
	newKey = strings.Join(srcsOrDstsInNewKeySlice, commaSepartor) + conn
	return
}
