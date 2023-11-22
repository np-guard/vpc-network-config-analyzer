package drawio

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// //////////////////////////////////////////////////////////////////////////////////////////////

type setAsKey string

var interfaceIndex map[interface{}]int

func (s *genericSet[T]) equal(s2 *genericSet[T]) bool {
	return s.asKey() == s2.asKey()
}

type genericSet[T comparable] map[T]bool
type subnetSet genericSet[TreeNodeInterface]
type groupTnSet genericSet[*GroupSubnetsSquareTreeNode]
type groupSet genericSet[*groupDataS]
type miniGroupSet genericSet[*miniGroupDataS]

// todo: remove???
func (s *subnetSet) asKey() setAsKey    { return ((*genericSet[TreeNodeInterface])(s)).asKey() }
func (s *groupTnSet) asKey() setAsKey   { return ((*genericSet[*GroupSubnetsSquareTreeNode])(s)).asKey() }
func (s *groupSet) asKey() setAsKey     { return ((*genericSet[*groupDataS])(s)).asKey() }
func (s *miniGroupSet) asKey() setAsKey { return ((*genericSet[*miniGroupDataS])(s)).asKey() }
func (s *miniGroupSet) equal(s2 *miniGroupSet) bool {
	return ((*genericSet[*miniGroupDataS])(s)).equal((*genericSet[*miniGroupDataS])(s2))
}

func (s *genericSet[T]) asKey() setAsKey {
	if interfaceIndex == nil {
		interfaceIndex = map[interface{}]int{}
	}
	ss := []string{}
	for i := range *s {
		if _, ok := interfaceIndex[i]; !ok {
			interfaceIndex[i] = len(interfaceIndex)
		}
		ss = append(ss, strconv.Itoa(interfaceIndex[i]))
	}
	sort.Strings(ss)
	return setAsKey(strings.Join(ss, ","))
}

/////////////////////////////////////////////////////////////////

type miniGroupDataS struct {
	subnets subnetSet
	zone    TreeNodeInterface
	located bool
}
type groupDataS struct {
	miniGroups        miniGroupSet
	topInnerGroups    []*groupDataS
	toSplitGroups     groupSet
	subnets           subnetSet
	treeNode          TreeNodeInterface
	name              string
	firstRow, lastRow int
	firstCol, lastCol int
	splitFrom         groupSet
	splitTo           groupSet
}

func newGroupDataS(name string, miniGroups miniGroupSet, tn TreeNodeInterface) *groupDataS {
	subnets := subnetSet{}
	for miniGroup := range miniGroups {
		for subnet := range miniGroup.subnets {
			subnets[subnet] = true
		}
	}
	return &groupDataS{
		miniGroups:    miniGroups,
		subnets:       subnets,
		treeNode:      tn,
		name:          name,
		toSplitGroups: groupSet{},
		splitFrom:     groupSet{},
		splitTo:       groupSet{},
	}
}

// ////////////////////////////////////////////////////////////////////////
type indexes struct {
	row, col int
}
type subnetsLayout struct {
	network          SquareTreeNodeInterface
	groups           []*groupDataS
	miniGroups       miniGroupSet
	miniGroupsMatrix [][]*miniGroupDataS
	subnetMatrix     [][]TreeNodeInterface
	subnetsIndexes   map[TreeNodeInterface]indexes
	zonesCol         map[TreeNodeInterface]int
}

func newSubnetsLayout(network SquareTreeNodeInterface) *subnetsLayout {
	return &subnetsLayout{
		network:        network,
		miniGroups:     miniGroupSet{},
		subnetsIndexes: map[TreeNodeInterface]indexes{},
		zonesCol:       map[TreeNodeInterface]int{},
	}
}

func (ly *subnetsLayout) layout() ([][]TreeNodeInterface, map[TreeNodeInterface]int) {
	ly.createGroupsDataS()
	topFakeGroup := newGroupDataS("", ly.miniGroups, nil)
	ly.splitSharing(topFakeGroup)
	ly.calcZoneOrder()
	ly.createMatrix()
	ly.layoutGroup(topFakeGroup, 0)
	ly.setSubnetsMatrix()
	ly.setGroupsIndexes()
	ly.createNewGroups()
	ly.fillGroupsSquares()
	return ly.subnetMatrix, ly.zonesCol
}

/////////////////////////////////////////////////////////////////////////////////////

func (ly *subnetsLayout) createMatrix() {
	maxDim := len(getAllNodes(ly.network))

	ly.miniGroupsMatrix = make([][]*miniGroupDataS, maxDim)
	for i := range ly.miniGroupsMatrix {
		ly.miniGroupsMatrix[i] = make([]*miniGroupDataS, maxDim)
	}

	ly.subnetMatrix = make([][]TreeNodeInterface, maxDim)
	for i := range ly.miniGroupsMatrix {
		ly.subnetMatrix[i] = make([]TreeNodeInterface, maxDim)
	}
}

func (group *groupDataS) isSubGroup(subGroup *groupDataS) bool {
	if len(group.miniGroups) == len(subGroup.miniGroups) {
		return false
	}
	for mg := range subGroup.miniGroups {
		if !group.miniGroups[mg] {
			return false
		}
	}
	return true
}

func (group *groupDataS) shareMiniGroup(gr2 *groupDataS) bool {
	for mg := range group.miniGroups {
		if gr2.miniGroups[mg] {
			return true
		}
	}
	return false
}

func (group *groupDataS) getVpc() *VpcTreeNode {
	if group.treeNode != nil {
		return group.treeNode.Parent().(*VpcTreeNode)
	}
	for g := range group.splitFrom {
		return g.getVpc()
	}
	return nil
}

func (group *groupDataS) reunion() {
	fmt.Println("group is reunion ", group.name)
	for gr := range group.splitTo {
		delete(gr.splitFrom, group)
	}
	group.splitTo = groupSet{}

}


// ////////////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) layoutGroup(group *groupDataS, minRow int) {
	minZoneCol, maxZoneCol := len(ly.zonesCol), -1
	for mg := range group.miniGroups {
		if minZoneCol > ly.zonesCol[mg.zone] {
			minZoneCol = ly.zonesCol[mg.zone]
		}
		if maxZoneCol < ly.zonesCol[mg.zone] {
			maxZoneCol = ly.zonesCol[mg.zone]
		}
	}
	firstRow := minRow
	for rIndex := firstRow; rIndex < len(ly.miniGroupsMatrix); rIndex++ {
		for cIndex := minZoneCol; cIndex <= maxZoneCol; cIndex++ {
			if ly.miniGroupsMatrix[rIndex][cIndex] != nil {
				firstRow = rIndex + 1
			}
		}
	}
	for _, innerGroup := range group.topInnerGroups {
		ly.layoutGroup(innerGroup, firstRow)
	}

	for miniGroup := range group.miniGroups {
		if miniGroup.located {
			continue
		}
		name := ""
		for s := range miniGroup.subnets {
			name += s.Label() + ","
		}
		emptyCell := firstRow
		for ly.miniGroupsMatrix[emptyCell][ly.zonesCol[miniGroup.zone]] != nil {
			emptyCell++
		}
		ly.miniGroupsMatrix[emptyCell][ly.zonesCol[miniGroup.zone]] = miniGroup
		miniGroup.located = true
		fmt.Printf("layout mini: %s (%d)\n", name, emptyCell)
	}

	lastRow := minRow
	for rIndex := lastRow; rIndex < len(ly.miniGroupsMatrix); rIndex++ {
		for cIndex := minZoneCol; cIndex <= maxZoneCol; cIndex++ {
			if ly.miniGroupsMatrix[rIndex][cIndex] != nil {
				lastRow = rIndex + 1
			}
		}
	}
	for rIndex := firstRow; rIndex <= lastRow; rIndex++ {
		for cIndex := minZoneCol; cIndex <= maxZoneCol; cIndex++ {
			if ly.miniGroupsMatrix[rIndex][cIndex] == nil {
				ly.miniGroupsMatrix[rIndex][cIndex] = &miniGroupDataS{}
			}
		}
	}

	fmt.Printf("end layout group %s %d-%d\n", group.name, firstRow, lastRow)

}


func (ly *subnetsLayout) setSubnetsMatrix() {
	rIndex := 0
	for _, row := range ly.miniGroupsMatrix {
		rowSize := 0
		for _, miniGroup := range row {
			if miniGroup == nil {
				continue
			}
			i := 0
			if rowSize < len(miniGroup.subnets) {
				rowSize = len(miniGroup.subnets)
			}
			for s := range miniGroup.subnets {
				ly.subnetMatrix[rIndex+i][ly.zonesCol[miniGroup.zone]] = s
				ly.subnetsIndexes[s] = indexes{rIndex + i, ly.zonesCol[miniGroup.zone]}
				i++
			}
		}
		rIndex += rowSize
	}
}
func (ly *subnetsLayout) setGroupsIndexes() {
	for _, group := range ly.groups {
		group.firstRow, group.firstCol, group.lastRow, group.lastCol = 100, 100, -1, -1
		for subnet := range group.subnets {
			subnetIndexes := ly.subnetsIndexes[subnet]
			if group.firstRow > subnetIndexes.row {
				group.firstRow = subnetIndexes.row
			}
			if group.firstCol > subnetIndexes.col {
				group.firstCol = subnetIndexes.col
			}
			if group.lastRow < subnetIndexes.row {
				group.lastRow = subnetIndexes.row
			}
			if group.lastCol < subnetIndexes.col {
				group.lastCol = subnetIndexes.col
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////

func (ly *subnetsLayout) allInnerGroups(group *groupDataS) []*groupDataS {
	allInnerGroups := []*groupDataS{}
	for _, group1 := range ly.groups {
		if group.isSubGroup(group1) {
			allInnerGroups = append(allInnerGroups, group1)
		}
	}
	return allInnerGroups
}

// ////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) splitSharing(group *groupDataS) {

	nonSplitGroup := groupSet{}
	for _, innerGroup := range ly.allInnerGroups(group) {
		if len(innerGroup.splitTo) == 0 {
			nonSplitGroup[innerGroup] = true
		}
	}
	for {
		innerGroups := groupSet{}
		for group1 := range nonSplitGroup {
			for group2 := range nonSplitGroup {
				if group2.isSubGroup(group1) {
					innerGroups[group1] = true
				}
			}
		}

		sharedMini := map[*groupDataS]groupSet{}

		for group1 := range nonSplitGroup {
			for group2 := range nonSplitGroup {
				if group1 != group2 {
					if !innerGroups[group1] && !innerGroups[group2] && group1.shareMiniGroup(group2) {
						if _, ok := sharedMini[group1]; !ok {
							sharedMini[group1] = groupSet{}
						}
						sharedMini[group1][group2] = true
					}
				}
			}
		}
		bestSharingScore := 0
		var mostSharedGroup *groupDataS
		for sharedGroup, sharedGroups := range sharedMini {
			if len(sharedGroups) > bestSharingScore ||
				(len(sharedGroups) == bestSharingScore && len(sharedGroup.miniGroups) < len(mostSharedGroup.miniGroups)) {
				bestSharingScore = len(sharedGroups)
				mostSharedGroup = sharedGroup
			}
		}
		if mostSharedGroup == nil {
			for innerGroup := range nonSplitGroup {
				if !innerGroups[innerGroup] {
					group.topInnerGroups = append(group.topInnerGroups, innerGroup)
				}
			}
			break
		}
		fmt.Println("group is split", mostSharedGroup.name)
		group.toSplitGroups[mostSharedGroup] = true
		delete(nonSplitGroup, mostSharedGroup)
	}

	if len(group.toSplitGroups) > 0 {
		ly.rearrangeGroup(group)
	}
	for _, topInnerGroup := range group.topInnerGroups {
		ly.splitSharing(topInnerGroup)

	}
}

// //////////////////////////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) rearrangeGroup(group *groupDataS) {
	splitMiniGroups := miniGroupSet{}
	for splitGroup := range group.toSplitGroups {
		for mn := range splitGroup.miniGroups {
			splitMiniGroups[mn] = true
		}
	}
	miniGroupToGroupSet := map[*miniGroupDataS]groupSet{}
	for _, group := range ly.allInnerGroups(group) {
		for miniGroup := range group.miniGroups {
			if splitMiniGroups[miniGroup] {
				if _, ok := miniGroupToGroupSet[miniGroup]; !ok {
					miniGroupToGroupSet[miniGroup] = groupSet{}
				}
				miniGroupToGroupSet[miniGroup][group] = true
			}
		}
	}
	groupSetToNewGroups := map[setAsKey]miniGroupSet{}
	keysToSet := map[setAsKey]groupSet{}
	for miniGroup, groupSet := range miniGroupToGroupSet {
		if _, ok := groupSetToNewGroups[groupSet.asKey()]; !ok {
			groupSetToNewGroups[groupSet.asKey()] = miniGroupSet{}
		}
		groupSetToNewGroups[groupSet.asKey()][miniGroup] = true
		keysToSet[groupSet.asKey()] = groupSet
	}
	for groups, miniGroups := range groupSetToNewGroups {
		var newGroup *groupDataS
		for _, gr := range ly.groups {
			if gr.miniGroups.equal(&miniGroups) {
				newGroup = gr
			}
		}
		if newGroup == nil {
			name := "created: "
			for miniGroup := range miniGroups {
				for s := range miniGroup.subnets {
					name += s.Label() + ","
				}
			}
			fmt.Println("group created ", name, " ", string(groups))
			newGroup = newGroupDataS(name, miniGroups, nil)
			ly.groups = append(ly.groups, newGroup)

			inTopGroup := false
			for _, topGroup := range group.topInnerGroups {
				if keysToSet[groups][topGroup] {
					inTopGroup = true
				}
			}
			if !inTopGroup {
				fmt.Println("group ", newGroup.name, " !inTopGroup")
				group.topInnerGroups = append(group.topInnerGroups, newGroup)
			}

		}
		for splitGroup := range group.toSplitGroups {
			if keysToSet[groups][splitGroup] {
				splitGroup.splitTo[newGroup] = true
				newGroup.splitFrom[splitGroup] = true
			}
		}
	}
}

// //////////////////////////////////////////
func (ly *subnetsLayout) createNewGroups() {
	tnToSplit := map[TreeNodeInterface]*groupDataS{}
	for _, group := range ly.groups {
		if len(group.splitTo) != 0 && group.treeNode != nil {
			if ly.checkGroupIntegrity(group) {
				group.reunion()
				continue
			}
			group.treeNode.SetNotShownInDrawio()
			tnToSplit[group.treeNode] = group
		}
	}
	for _, group := range ly.groups {
		if group.treeNode != nil && !group.treeNode.NotShownInDrawio() && !ly.checkGroupIntegrity(group) {
			fmt.Println("group ", group.name, " is not integrate")
		}
	}
	for _, group := range ly.groups {
		if len(group.splitTo) == 0 && group.treeNode == nil && len(group.splitFrom) > 0 {
			subnets := []SquareTreeNodeInterface{}
			for miniGroup := range group.miniGroups {
				for subnet := range miniGroup.subnets {
					subnets = append(subnets, subnet.(SquareTreeNodeInterface))
				}
			}
			if len(subnets) == 1 {
				group.treeNode = subnets[0]
			} else {
				group.treeNode = GroupedSubnetsSquare(group.getVpc(), subnets)
			}
		}
	}

	for _, con := range getAllNodes(ly.network) {
		if !con.IsLine() {
			continue
		}
		src, dst := con.(LineTreeNodeInterface).Src(), con.(LineTreeNodeInterface).Dst()
		srcGroup, dstGroup := tnToSplit[src], tnToSplit[dst]
		if srcGroup == nil && dstGroup == nil {
			continue
		}
		allSrcs, allDsts := []TreeNodeInterface{src}, []TreeNodeInterface{dst}
		if srcGroup != nil {
			allSrcs = []TreeNodeInterface{}
			for gr := range srcGroup.splitTo {
				allSrcs = append(allSrcs, gr.treeNode)
			}
		}
		if dstGroup != nil {
			allDsts = []TreeNodeInterface{}
			for gr := range dstGroup.splitTo {
				allDsts = append(allDsts, gr.treeNode)
			}
		}
		for _, sTn := range allSrcs {
			for _, dTn := range allDsts {
				NewConnectivityLineTreeNode(ly.network, sTn, dTn, con.(*ConnectivityTreeNode).directed, con.(*ConnectivityTreeNode).name)
			}
		}
		con.SetNotShownInDrawio()
	}
}

func (ly *subnetsLayout) fillGroupsSquares() {
	for _, group := range ly.groups {
		if group.treeNode == nil || group.treeNode.NotShownInDrawio() {
			continue
		}
		for r := group.firstRow; r <= group.lastRow; r++ {
			for c := group.firstCol; c <= group.lastCol; c++ {
				if ly.subnetMatrix[r][c] == nil {
					ly.subnetMatrix[r][c] = ly.network
				}
			}
		}
	}

}

func (ly *subnetsLayout) checkGroupIntegrity(group *groupDataS) bool {
	nSubnets := 0
	for r := group.firstRow; r <= group.lastRow; r++ {
		for c := group.firstCol; c <= group.lastCol; c++ {
			subnet := ly.subnetMatrix[r][c]
			if subnet != nil {
				if !group.subnets[subnet] {
					return false
				}
				nSubnets++
			}
		}
	}

	return nSubnets == len(group.subnets)
}

// ////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) calcZoneOrder() {
	zoneConnections := map[TreeNodeInterface]map[TreeNodeInterface]int{}
	for _, group := range ly.groups {
		for miniGroup1 := range group.miniGroups {
			for miniGroup2 := range group.miniGroups {
				if miniGroup1 != miniGroup2 && miniGroup1.zone != miniGroup2.zone {
					if _, ok := zoneConnections[miniGroup1.zone]; !ok {
						zoneConnections[miniGroup1.zone] = map[TreeNodeInterface]int{}
					}
					zoneConnections[miniGroup1.zone][miniGroup2.zone] += 1
				}
			}
		}
	}
	zoneOrder := []TreeNodeInterface{}

	for {

		for i := 1; i < len(zoneOrder)-1; i++ {
			delete(zoneConnections, zoneOrder[i])
		}
		for _, zone := range zoneOrder {
			for _, zScores := range zoneConnections {
				delete(zScores, zone)
			}
		}
		for z, score := range zoneConnections {
			if len(score) == 0 {
				delete(zoneConnections, z)
			}
		}
		if len(zoneConnections) == 0 {
			break
		}

		var zoneToAdd TreeNodeInterface
		addToRight := 1
		if len(zoneOrder) > 0 {
			zonesAtEdges := []TreeNodeInterface{zoneOrder[0], zoneOrder[len(zoneOrder)-1]}
			bestScores := []int{0, 0}
			zonesWithBestScore := []TreeNodeInterface{nil, nil}
			for i, zToChoose := range zonesAtEdges {
				for z, score := range zoneConnections[zToChoose] {
					if bestScores[i] < score {
						bestScores[i] = score
						zonesWithBestScore[i] = z
					}
				}
			}
			if bestScores[0] > bestScores[1] {
				addToRight = 0
			}
			if bestScores[addToRight] > 0 {
				zoneToAdd = zonesWithBestScore[addToRight]
			}

		}
		if zoneToAdd == nil {
			bestScore := 0
			for z, friendsScore := range zoneConnections {
				for _, score := range friendsScore {
					if bestScore < score {
						bestScore = score
						zoneToAdd = z
					}
				}
			}
		}
		if addToRight == 1 {
			zoneOrder = append(zoneOrder, zoneToAdd)
		} else {
			zoneOrder = append([]TreeNodeInterface{zoneToAdd}, zoneOrder...)
		}
	}
	for _, zone := range zoneOrder {
		fmt.Print(" ", zone.Label())
	}
	fmt.Println("")
	for i, z := range zoneOrder {
		ly.zonesCol[z] = i
	}
	for miniGroup := range ly.miniGroups {
		if _, ok := ly.zonesCol[miniGroup.zone]; !ok {
			ly.zonesCol[miniGroup.zone] = len(ly.zonesCol)
		}
	}
}

//////////////////////////////////////////////////////////////////////////

func (ly *subnetsLayout) createGroupsDataS() {
	subnetToGroups := ly.sortSubnets()
	groupSetToSubnetSet := sortSubnetsByZoneAndGroups(subnetToGroups)
	ly.createMiniGroups(groupSetToSubnetSet)
	ly.createGroups(subnetToGroups)
	sort.Slice(ly.groups, func(i, j int) bool {
		return len(ly.groups[i].miniGroups) > len(ly.groups[j].miniGroups)
	})
}

//////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////

func (ly *subnetsLayout) groupTreeNodes() groupTnSet {
	allGroups := groupTnSet{}
	for _, tn := range getAllNodes(ly.network) {
		if reflect.TypeOf(tn).Elem() == reflect.TypeOf(GroupSubnetsSquareTreeNode{}) {
			allGroups[tn.(*GroupSubnetsSquareTreeNode)] = true
		}
	}
	return allGroups
}

func (ly *subnetsLayout) sortSubnets() map[TreeNodeInterface]groupTnSet {
	allGroups := ly.groupTreeNodes()
	subnetToGroups := map[TreeNodeInterface]groupTnSet{}
	for group := range allGroups {
		for _, subnet := range group.groupedSubnets {
			if _, ok := subnetToGroups[subnet]; !ok {
				subnetToGroups[subnet] = groupTnSet{}
			}
			subnetToGroups[subnet][group] = true
		}
	}
	return subnetToGroups
}
func sortSubnetsByZoneAndGroups(subnetToGroups map[TreeNodeInterface]groupTnSet) map[setAsKey]map[TreeNodeInterface]subnetSet {
	groupSetToSubnetSet := map[setAsKey]map[TreeNodeInterface]subnetSet{}
	for subnet, groups := range subnetToGroups {
		if _, ok := groupSetToSubnetSet[groups.asKey()]; !ok {
			groupSetToSubnetSet[groups.asKey()] = map[TreeNodeInterface]subnetSet{}
		}
		zone := subnet.Parent()
		if _, ok := groupSetToSubnetSet[groups.asKey()][zone]; !ok {
			groupSetToSubnetSet[groups.asKey()][subnet.Parent()] = subnetSet{}
		}
		groupSetToSubnetSet[groups.asKey()][zone][subnet] = true
	}
	return groupSetToSubnetSet
}

func (ly *subnetsLayout) createMiniGroups(groupSetToSubnetSet map[setAsKey]map[TreeNodeInterface]subnetSet) {
	for _, zoneMiniGroup := range groupSetToSubnetSet {
		for zone, miniGroup := range zoneMiniGroup {
			miniGroupData := miniGroupDataS{subnets: miniGroup, zone: zone}
			ly.miniGroups[&miniGroupData] = true
		}
	}
}
func (ly *subnetsLayout) createGroups(subnetToGroups map[TreeNodeInterface]groupTnSet) {
	groupToMiniGroups := map[TreeNodeInterface]miniGroupSet{}
	for miniGroup := range ly.miniGroups {
		for subnet := range miniGroup.subnets {
			for group := range subnetToGroups[subnet] {
				if _, ok := groupToMiniGroups[group]; !ok {
					groupToMiniGroups[group] = miniGroupSet{}
				}
				groupToMiniGroups[group][miniGroup] = true
			}
		}
	}
	for groupTn, miniGroups := range groupToMiniGroups {
		groupData := newGroupDataS(groupTn.Label(), miniGroups, groupTn)
		ly.groups = append(ly.groups, groupData)
	}

}
