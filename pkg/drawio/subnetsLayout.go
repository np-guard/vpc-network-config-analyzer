package drawio

import (
	"maps"
	"sort"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// //////////////////////////////////////////////////////////////////////////////////////////////
// subnetsLayout struct is a struct for layout subnets when the network is in subnet mode.
// the input of the layout algorithm is the groups of subnets,
// and the output is a matrix of subnets, representing the subnets location on the drawio canvas.
// the location of the groups squares is determinate later by the location of the subnets.
// the layout algorithm should make sure that all the group subnets, and only the group subnets should be inside the group squares.
// since some of the subnets can be in the more than one group, the solution is not trivial.
// and is some cases we must split a group to smaller groups, and delete the original group.
//
// the algorithm uses the concept of miniGroup:
// a miniGroup is a set of subnets. all the subnets in a miniGroup are sharing same groups, and the same zone.
// all the subnet in the miniGroup will be alongside each other, so instead of layout the subnets, we layout miniGroups
// a group is not a set of subnets, but a set of miniGroups
//
// the main phases of the layout algorithm:
// 1. sort the subnets to miniGroups, sort the miniGroups to their groups:
//   the output is a list of groups, each group has a list of miniGroups
// 2. create a tree of groups - the children of a group are set of groups that do not intersect, and hold only miniGroups of the group
//    (in this phase new groups are created, by splitting  groups to smaller groups)
// 3. layout the groups
// 4. create new treeNodes of the new groupSquares and new connectors
// //////////////////////////////////////////////////////////////////////////////////////////////

type subnetSet = common.GenericSet[TreeNodeInterface]
type groupTnSet = common.GenericSet[TreeNodeInterface]
type groupSet = common.GenericSet[*groupDataS]
type miniGroupSet = common.GenericSet[*miniGroupDataS]
type setAsKey = common.SetAsKey

/////////////////////////////////////////////////////////////////

type miniGroupDataS struct {
	subnets subnetSet
	zone    TreeNodeInterface
	located bool
}

// ///////////////////////////////////////////////////////////////////
// groupsDataS is the struct representing a group.
// they are creating if the first step, when sorting the miniGroups to groups.
// some more are created when groups are split to smaller group
// /////////////////////////////////////////////////////////////////
type groupDataS struct {
	// miniGroups - set of the miniGroups of the group
	// subnets - set of all the subnets  of the group
	miniGroups miniGroupSet
	subnets    subnetSet
	// treeNode - the relevant treeNode of the group, for most groups we already have a treeNode, for new groups, we create a new treeNode
	treeNode TreeNodeInterface
	// children - the children in the tree of groups
	children groupSet
	// toSplitGroups - toSplitGroups are all the subgroups of the group that will be split. these groups will not be te the groups tree
	toSplitGroups groupSet
	// splitFrom - if a group was created during splitting, splitFrom is the groups that the group was split from
	// splitTo - if a group was split, splitTo is the groups that the group was split to
	splitFrom groupSet
	splitTo   groupSet
}

// fakeSubnet and fakeMiniGroup are used as space holders in the matrixes
var fakeSubnet TreeNodeInterface = &SubnetTreeNode{}
var fakeMiniGroup *miniGroupDataS = &miniGroupDataS{subnets: subnetSet{}}

func newGroupDataS(miniGroups miniGroupSet, tn TreeNodeInterface) *groupDataS {
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
		children:      groupSet{},
		toSplitGroups: groupSet{},
		splitFrom:     groupSet{},
		splitTo:       groupSet{},
	}
}

// /////////////////////////////////////////////////////////////////
func (group *groupDataS) isInnerGroup(subGroup *groupDataS) bool {
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
	for gr := range group.splitTo {
		delete(gr.splitFrom, group)
	}
	group.splitTo = groupSet{}
}

// ////////////////////////////////////////////////////////////////////////
type indexes struct {
	row, col int
}
type subnetsLayout struct {
	network           SquareTreeNodeInterface
	groups            []*groupDataS
	miniGroups        miniGroupSet
	miniGroupsMatrix  [][]*miniGroupDataS
	subnetMatrix      [][]TreeNodeInterface
	subnetsIndexes    map[TreeNodeInterface]indexes
	zonesCol          map[TreeNodeInterface]int
	treeNodesToGroups map[TreeNodeInterface]*groupDataS
	topFakeGroup      *groupDataS
}

func newSubnetsLayout(network SquareTreeNodeInterface) *subnetsLayout {
	return &subnetsLayout{
		network:           network,
		miniGroups:        miniGroupSet{},
		subnetsIndexes:    map[TreeNodeInterface]indexes{},
		zonesCol:          map[TreeNodeInterface]int{},
		treeNodesToGroups: map[TreeNodeInterface]*groupDataS{},
	}
}

// layout() - the top function, with the four steps of the algorithm:
func (ly *subnetsLayout) layout() {
	// create a list of groups and miniGroups:
	ly.createGroupsDataS()
	ly.topFakeGroup = newGroupDataS(ly.miniGroups, nil)
	// create the group tree:
	ly.createGroupSubTree(ly.topFakeGroup)
	// layout the groups:
	ly.layoutGroups()
	// create the new treeNodes:
	ly.createNewTreeNodes()
}

// //////////////////////////////////////////////////////////
// createGroupsDataS() - sorting the subnets to miniGroups and groups
// the output is a list of miniGroups and list of groups. (each group holds a set of miniGroups)
// a miniGroup is a set of subnets from the same zone, each subnet in the set are at the same set of groups.
// phases:
// 1. sort subnets to groups (map: subnet -> set of groups)
// 2. sort sets of groups to set of subnets (map: group set -> subnet Set)
// 3. create miniGroups
// 4. create the groups
func (ly *subnetsLayout) createGroupsDataS() {
	subnetToGroups := ly.sortSubnets()
	groupSetToSubnetSet := sortSubnetsByZoneAndGroups(subnetToGroups)
	ly.createMiniGroups(groupSetToSubnetSet)
	ly.createGroups(subnetToGroups)
	sort.Slice(ly.groups, func(i, j int) bool {
		return len(ly.groups[i].miniGroups) > len(ly.groups[j].miniGroups)
	})
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
// createGroupSubTree() is a recursive method to create the tree of groups.
// the root of the tree is a fake group that holds all the miniGroups
// the creation of the tree might involve splitting groups to smaller new groups.
// (the split group is not in the tree)
// for example, consider the following list of groups:
// (m1,m2,m3), (m2,m3,m4,m5), (m4,m5,m6), (m4, m5)
// the algorithm will split (m2,m3,m4,m5). it will create a new group (m2,m3)
// the tree will look like:
// (m1,m2,m3,m4,m5,m6) -> (m1,m2,m3), (m4,m5,m6)
// (m1,m2,m3) -> (m2,m3)
// (m4,m5,m6) -> (m4,m5)

// the main challenge of createGroupSubTree() is to choose which groups to split
// the candidates are all the subgroups of the group, which are not a subgroup of other subgroup (aka nonSplitNotInnerGroups).
// each iteration of the loop:
//     - updates nonSplitNotInnerGroups,
//     - choose a sub group to split,
//     - continue the loop till all nonSplitNotInnerGroups do not intersect each other.
// the subgroups that remained at nonSplitNotInnerGroups, are set to be the children of the group
// the sub groups that was chosen to be split, are split to new groups at createGroupsFromSplitGroups()

func (ly *subnetsLayout) createGroupSubTree(group *groupDataS) {
	nonSplitGroups := ly.innerGroupsOfAGroup(group)
	for innerGroup := range nonSplitGroups {
		if len(innerGroup.splitTo) > 0 {
			delete(nonSplitGroups, innerGroup)
		}
	}
	for {
		nonSplitNotInnerGroups := nonInnerGroups(nonSplitGroups)
		intersectGroups := intersectGroups(nonSplitNotInnerGroups)
		mostSharedGroup := chooseGroupToSplit(intersectGroups)
		if mostSharedGroup == nil {
			group.children = nonSplitNotInnerGroups
			break
		}
		group.toSplitGroups[mostSharedGroup] = true
		delete(nonSplitGroups, mostSharedGroup)
	}

	if len(group.toSplitGroups) > 0 {
		ly.createGroupsFromSplitGroups(group)
	}
	for topInnerGroup := range group.children {
		ly.createGroupSubTree(topInnerGroup)
	}
}

// ///////////////////////////////////////////////////////////////////////////
// ///////////////////////////////////////////////////////////////////////////
// the output of the layout algorithm is a matrix of miniGroups, later converted to a matrix of subnets
// each column is dedicated to a different zone
// layoutGroups() has two main steps:
// 1. calc the zone order - try to put zones that share the same group next to each other
// 2. layout groups - a recursive call to set the miniGroups locations on the matrix
// see documentation of calcZoneOrder() and layoutGroup()
func (ly *subnetsLayout) layoutGroups() {
	ly.calcZoneOrder()
	ly.createMatrixes()
	ly.layoutGroup(ly.topFakeGroup, 0)
	ly.setSubnetsMatrix()
}

// ///////////////////////////////////////////////////////////////////////////
// ///////////////////////////////////////////////////////////////////////////
// createNewTreeNodes() do the follows:
// check if a split group can somehow be shown on the canvas, if not, mark them as doNotShowOnDrawio
// created treeNodes for the groups that was created during the splitting
// creates new connections that replace the connections of groups that was split
func (ly *subnetsLayout) createNewTreeNodes() {
	ly.doNotShowSplitGroups()
	ly.createNewGroupsTreeNodes()
	ly.createNewLinesTreeNodes()
}

// ////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////

func (ly *subnetsLayout) sortSubnets() map[TreeNodeInterface]groupTnSet {
	subnetToGroups := map[TreeNodeInterface]groupTnSet{}
	for group := range ly.groupsTreeNodes() {
		for _, subnet := range group.(*GroupSubnetsSquareTreeNode).groupedSubnets {
			if _, ok := subnetToGroups[subnet]; !ok {
				subnetToGroups[subnet] = groupTnSet{}
			}
			subnetToGroups[subnet][group] = true
		}
	}
	return subnetToGroups
}

func (ly *subnetsLayout) groupsTreeNodes() groupTnSet {
	allGroups := groupTnSet{}
	for _, tn := range getAllNodes(ly.network) {
		if tn.IsSquare() && tn.(SquareTreeNodeInterface).IsGroupSubnetsSquare() {
			allGroups[tn] = true
		}
	}
	return allGroups
}

func sortSubnetsByZoneAndGroups(subnetToGroups map[TreeNodeInterface]groupTnSet) map[setAsKey]map[TreeNodeInterface]subnetSet {
	groupSetToSubnetSet := map[setAsKey]map[TreeNodeInterface]subnetSet{}
	for subnet, groups := range subnetToGroups {
		if _, ok := groupSetToSubnetSet[groups.AsKey()]; !ok {
			groupSetToSubnetSet[groups.AsKey()] = map[TreeNodeInterface]subnetSet{}
		}
		zone := subnet.Parent()
		if _, ok := groupSetToSubnetSet[groups.AsKey()][zone]; !ok {
			groupSetToSubnetSet[groups.AsKey()][subnet.Parent()] = subnetSet{}
		}
		groupSetToSubnetSet[groups.AsKey()][zone][subnet] = true
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
		groupData := newGroupDataS(miniGroups, groupTn)
		ly.treeNodesToGroups[groupTn] = groupData
		ly.groups = append(ly.groups, groupData)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////

func (ly *subnetsLayout) innerGroupsOfAGroup(group *groupDataS) groupSet {
	allInnerGroups := groupSet{}
	for _, group1 := range ly.groups {
		if group.isInnerGroup(group1) {
			allInnerGroups[group1] = true
		}
	}
	return allInnerGroups
}

func nonInnerGroups(groups groupSet) groupSet {
	nonInnerGroups := maps.Clone(groups)
	for group1 := range groups {
		for group2 := range groups {
			if group2.isInnerGroup(group1) {
				delete(nonInnerGroups, group1)
			}
		}
	}
	return nonInnerGroups
}

func intersectGroups(groups groupSet) map[*groupDataS]groupSet {
	intersectGroups := map[*groupDataS]groupSet{}

	for group1 := range groups {
		for group2 := range groups {
			if group1 != group2 {
				if group1.miniGroups.IsIntersect(group2.miniGroups) {
					if _, ok := intersectGroups[group1]; !ok {
						intersectGroups[group1] = groupSet{}
					}
					intersectGroups[group1][group2] = true
				}
			}
		}
	}
	return intersectGroups
}

func chooseGroupToSplit(intersectGroups map[*groupDataS]groupSet) *groupDataS {
	bestSharingScore := 0
	var mostSharedGroup *groupDataS
	for sharedGroup, sharedGroups := range intersectGroups {
		if len(sharedGroups) > bestSharingScore ||
			(len(sharedGroups) == bestSharingScore && len(sharedGroup.miniGroups) < len(mostSharedGroup.miniGroups)) {
			bestSharingScore = len(sharedGroups)
			mostSharedGroup = sharedGroup
		}
	}
	return mostSharedGroup
}

// ////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) createGroupsFromSplitGroups(group *groupDataS) {
	miniGroupToGroupSet := ly.sortSplitMiniGroupsByGroupSet(group)
	groupSetToMiniGroups, keysToGroupSet := groupSetToMiniGroups(miniGroupToGroupSet)

	for groupsKey, miniGroups := range groupSetToMiniGroups {
		groups := keysToGroupSet[groupsKey]
		ly.newGroupFromSplitMiniGroups(group, miniGroups, groups)
	}
}

func (ly *subnetsLayout) sortSplitMiniGroupsByGroupSet(group *groupDataS) map[*miniGroupDataS]groupSet {
	splitMiniGroups := miniGroupSet{}
	for splitGroup := range group.toSplitGroups {
		for mn := range splitGroup.miniGroups {
			splitMiniGroups[mn] = true
		}
	}
	miniGroupToGroupSet := map[*miniGroupDataS]groupSet{}
	for group := range ly.innerGroupsOfAGroup(group) {
		for miniGroup := range group.miniGroups {
			if splitMiniGroups[miniGroup] {
				if _, ok := miniGroupToGroupSet[miniGroup]; !ok {
					miniGroupToGroupSet[miniGroup] = groupSet{}
				}
				miniGroupToGroupSet[miniGroup][group] = true
			}
		}
	}
	return miniGroupToGroupSet
}

func groupSetToMiniGroups(miniGroupToGroupSet map[*miniGroupDataS]groupSet) (
	groupSetToMiniGroups map[setAsKey]miniGroupSet,
	keysToGroupSet map[setAsKey]groupSet) {
	groupSetToMiniGroups = map[setAsKey]miniGroupSet{}
	keysToGroupSet = map[setAsKey]groupSet{}
	for miniGroup, groupSet := range miniGroupToGroupSet {
		if _, ok := groupSetToMiniGroups[groupSet.AsKey()]; !ok {
			groupSetToMiniGroups[groupSet.AsKey()] = miniGroupSet{}
		}
		groupSetToMiniGroups[groupSet.AsKey()][miniGroup] = true
		keysToGroupSet[groupSet.AsKey()] = groupSet
	}
	return groupSetToMiniGroups, keysToGroupSet
}

func (ly *subnetsLayout) newGroupFromSplitMiniGroups(group *groupDataS, miniGroups miniGroupSet, groups groupSet) {
	var newGroup *groupDataS
	for _, gr := range ly.groups {
		if maps.Equal(gr.miniGroups, miniGroups) {
			newGroup = gr
			break
		}
	}
	if newGroup == nil {
		newGroup = newGroupDataS(miniGroups, nil)
		ly.groups = append(ly.groups, newGroup)

		inTopGroup := false
		for topGroup := range group.children {
			if groups[topGroup] {
				inTopGroup = true
				break
			}
		}
		if !inTopGroup {
			group.children[newGroup] = true
		}
	}
	for splitGroup := range group.toSplitGroups {
		if groups[splitGroup] {
			splitGroup.splitTo[newGroup] = true
			newGroup.splitFrom[splitGroup] = true
		}
	}
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
// calcZoneOrder()  set the order of the zones in the matrix (every zone has one column)
// the output of the is a list of zones
// 1. for every pair of zones, calc the score of the pair
// 2. start a slice of a size of two, with the pair that has the highest score
// 3. in a loop  - choose the best pair (z1,z2) such as z1 not in the slice and z2 in beginning/end of the slice. add z1 to the slice

func (ly *subnetsLayout) calcZoneOrder() {
	zonesScores := ly.calcZonePairScores()
	var zoneOrder []TreeNodeInterface
	zoneOrders := [][]TreeNodeInterface{}
	for len(zonesScores) > 0 {
		zoneToAdd, addToRight, newZoneOrder := chooseZoneToAdd(zonesScores, zoneOrder)
		if newZoneOrder {
			if len(zoneOrder) > 0 {
				zoneOrders = append(zoneOrders, zoneOrder)
			}
			zoneOrder = []TreeNodeInterface{}
		}
		if addToRight == 1 {
			zoneOrder = append(zoneOrder, zoneToAdd)
		} else {
			zoneOrder = append([]TreeNodeInterface{zoneToAdd}, zoneOrder...)
		}

		if len(zoneOrder) > 2 {
			if addToRight == 1 {
				delete(zonesScores, zoneOrder[len(zoneOrder)-2])
			} else {
				delete(zonesScores, zoneOrder[1])
			}
		}
		for _, zScores := range zonesScores {
			delete(zScores, zoneToAdd)
		}
		for z, score := range zonesScores {
			if len(score) == 0 {
				delete(zonesScores, z)
			}
		}
	}
	if len(zoneOrder) > 0 {
		zoneOrders = append(zoneOrders, zoneOrder)
	}
	ly.setZonesCol(zoneOrders)
}

func (ly *subnetsLayout) setZonesCol(zoneOrders [][]TreeNodeInterface) {
	// zoneOrders of the same VPCs must be together
	// sorting the zoneOrders by their VPCs:
	vpcToOrders := map[TreeNodeInterface][][]TreeNodeInterface{}
	for _, order := range zoneOrders {
		vpc := order[0].Parent()
		vpcToOrders[vpc] = append(vpcToOrders[vpc], order)
	}
	i := 0
	for _, vpcOrders := range vpcToOrders {
		for _, order := range vpcOrders {
			for _, z := range order {
				ly.zonesCol[z] = i
				i++
			}
		}
	}
	for miniGroup := range ly.miniGroups {
		if _, ok := ly.zonesCol[miniGroup.zone]; !ok {
			ly.zonesCol[miniGroup.zone] = len(ly.zonesCol)
		}
	}
}

func (ly *subnetsLayout) calcZonePairScores() map[TreeNodeInterface]map[TreeNodeInterface]int {
	zonesScores := map[TreeNodeInterface]map[TreeNodeInterface]int{}
	for _, group := range ly.groups {
		for miniGroup1 := range group.miniGroups {
			for miniGroup2 := range group.miniGroups {
				if miniGroup1.zone != miniGroup2.zone {
					if _, ok := zonesScores[miniGroup1.zone]; !ok {
						zonesScores[miniGroup1.zone] = map[TreeNodeInterface]int{}
					}
					zonesScores[miniGroup1.zone][miniGroup2.zone] += 1
				}
			}
		}
	}
	return zonesScores
}
func chooseZoneToAdd(zonesScores map[TreeNodeInterface]map[TreeNodeInterface]int,
	zoneOrder []TreeNodeInterface) (zoneToAdd TreeNodeInterface, addToRight int, newZoneOrder bool) {
	addToRight = 1
	if len(zoneOrder) > 0 {
		zonesAtEdges := []TreeNodeInterface{zoneOrder[0], zoneOrder[len(zoneOrder)-1]}
		bestScores := []int{0, 0}
		zonesWithBestScore := []TreeNodeInterface{nil, nil}
		for i, zToChoose := range zonesAtEdges {
			for z, score := range zonesScores[zToChoose] {
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
		// in case the zoneOrder is empty. or there are no score with one of the edge zones
		newZoneOrder = true
		bestScore := 0
		for z, friendsScore := range zonesScores {
			for _, score := range friendsScore {
				if score > bestScore {
					bestScore = score
					zoneToAdd = z
				}
			}
		}
	}
	return zoneToAdd, addToRight, newZoneOrder
}

func (ly *subnetsLayout) createMatrixes() {
	ly.miniGroupsMatrix = make([][]*miniGroupDataS, len(ly.miniGroups))
	for i := range ly.miniGroupsMatrix {
		ly.miniGroupsMatrix[i] = make([]*miniGroupDataS, len(ly.zonesCol))
	}
	ly.subnetMatrix = make([][]TreeNodeInterface, len(ly.topFakeGroup.subnets))
	for i := range ly.subnetMatrix {
		ly.subnetMatrix[i] = make([]TreeNodeInterface, len(ly.zonesCol))
	}
}

// /////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////
// layoutGroup() is a recursive method to layout the group
// phases:
// 1. calc min and max Clos
// 2. calc the first row of the group
// 3. layout all the children
// 4. layout the miniGroups of the group
// 5. calc the last group.
// 6. fill the square [firstRow-lastRow, minCol-maxCol] with a fake miniGroups, as space holders
func (ly *subnetsLayout) layoutGroup(group *groupDataS, parentFirstRow int) {
	childrenOrder := group.children.AsList()
	sort.Slice(childrenOrder, func(i, j int) bool {
		return len(childrenOrder[i].miniGroups) > len(childrenOrder[j].miniGroups)
	})

	minZoneCol, maxZoneCol, firstRow := ly.calcGroupLayoutBorders(group, parentFirstRow)
	for _, child := range childrenOrder {
		ly.layoutGroup(child, firstRow)
	}
	for miniGroup := range group.miniGroups {
		if miniGroup.located {
			continue
		}
		emptyCellRow := firstRow
		for ly.miniGroupsMatrix[emptyCellRow][ly.zonesCol[miniGroup.zone]] != nil {
			emptyCellRow++
		}
		ly.miniGroupsMatrix[emptyCellRow][ly.zonesCol[miniGroup.zone]] = miniGroup
		miniGroup.located = true
	}

	if group != ly.topFakeGroup {
		lastRow := parentFirstRow
		for rIndex := lastRow; rIndex < len(ly.miniGroupsMatrix); rIndex++ {
			for cIndex := minZoneCol; cIndex <= maxZoneCol; cIndex++ {
				if ly.miniGroupsMatrix[rIndex][cIndex] != nil {
					lastRow = rIndex
				}
			}
		}
		for rIndex := firstRow; rIndex <= lastRow; rIndex++ {
			for cIndex := minZoneCol; cIndex <= maxZoneCol; cIndex++ {
				if ly.miniGroupsMatrix[rIndex][cIndex] == nil {
					ly.miniGroupsMatrix[rIndex][cIndex] = fakeMiniGroup
				}
			}
		}
	}
}

func (ly *subnetsLayout) calcGroupLayoutBorders(group *groupDataS, parentFirstRow int) (minZoneCol, maxZoneCol, firstRow int) {
	minZoneCol, maxZoneCol = len(ly.zonesCol), -1
	for mg := range group.miniGroups {
		if minZoneCol > ly.zonesCol[mg.zone] {
			minZoneCol = ly.zonesCol[mg.zone]
		}
		if maxZoneCol < ly.zonesCol[mg.zone] {
			maxZoneCol = ly.zonesCol[mg.zone]
		}
	}
	firstRow = parentFirstRow
	for rIndex := firstRow; rIndex < len(ly.miniGroupsMatrix); rIndex++ {
		for cIndex := minZoneCol; cIndex <= maxZoneCol; cIndex++ {
			if ly.miniGroupsMatrix[rIndex][cIndex] != nil {
				firstRow = rIndex + 1
			}
		}
	}
	return minZoneCol, maxZoneCol, firstRow
}

func (ly *subnetsLayout) setSubnetsMatrix() {
	rIndex := 0
	for _, row := range ly.miniGroupsMatrix {
		rowSize := 0
		for colIndex, miniGroup := range row {
			if miniGroup == nil {
				continue
			}
			i := 0
			if rowSize < len(miniGroup.subnets) {
				rowSize = len(miniGroup.subnets)
			}
			for s := range miniGroup.subnets {
				ly.subnetMatrix[rIndex+i][colIndex] = s
				ly.subnetsIndexes[s] = indexes{rIndex + i, colIndex}
				i++
			}
		}
		for colIndex, miniGroup := range row {
			if miniGroup == nil {
				continue
			}
			for i := 0; i < rowSize; i++ {
				if ly.subnetMatrix[rIndex+i][colIndex] == nil {
					ly.subnetMatrix[rIndex+i][colIndex] = fakeSubnet
				}
			}
		}
		rIndex += rowSize
	}
}

func (ly *subnetsLayout) doNotShowSplitGroups() {
	for _, group := range ly.groups {
		if len(group.splitTo) != 0 && group.treeNode != nil {
			if ly.canShowGroup(group) {
				group.reunion()
				continue
			}
			group.treeNode.SetNotShownInDrawio()
		}
	}
}

func (ly *subnetsLayout) createNewGroupsTreeNodes() {
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
			ly.treeNodesToGroups[group.treeNode] = group
		}
	}
}

func (ly *subnetsLayout) createNewLinesTreeNodes() {
	for _, con := range getAllNodes(ly.network) {
		if !con.IsLine() {
			continue
		}
		srcTn, dstTn := con.(LineTreeNodeInterface).Src(), con.(LineTreeNodeInterface).Dst()
		if !srcTn.NotShownInDrawio() && !dstTn.NotShownInDrawio() {
			continue
		}
		allSrcTns, allDstTns := ly.allSplitTreeNodes(srcTn), ly.allSplitTreeNodes(dstTn)
		handledSrcTns := groupTnSet{}
		for sTn := range allSrcTns {
			for dTn := range allDstTns {
				switch {
				case allSrcTns[dTn] && allDstTns[sTn] && handledSrcTns[dTn]:
				case allSrcTns[dTn] && allDstTns[sTn]:
					NewConnectivityLineTreeNode(ly.network, sTn, dTn, false, con.(*ConnectivityTreeNode).name)
				default:
					NewConnectivityLineTreeNode(ly.network, sTn, dTn, con.(*ConnectivityTreeNode).directed, con.(*ConnectivityTreeNode).name)
				}
			}
			handledSrcTns[sTn] = true
		}
		con.SetNotShownInDrawio()
	}
}

func (ly *subnetsLayout) allSplitTreeNodes(tn TreeNodeInterface) groupTnSet {
	group := ly.treeNodesToGroups[tn]
	allTns := groupTnSet{tn: true}
	if group != nil && len(group.splitTo) > 0 {
		allTns = groupTnSet{}
		for gr := range group.splitTo {
			allTns[gr.treeNode] = true
		}
	}
	return allTns
}

func (ly *subnetsLayout) canShowGroup(group *groupDataS) bool {
	firstRow, firstCol, lastRow, lastCol := len(ly.subnetMatrix), len(ly.subnetMatrix[0]), -1, -1
	for subnet := range group.subnets {
		subnetIndexes := ly.subnetsIndexes[subnet]
		if firstRow > subnetIndexes.row {
			firstRow = subnetIndexes.row
		}
		if firstCol > subnetIndexes.col {
			firstCol = subnetIndexes.col
		}
		if lastRow < subnetIndexes.row {
			lastRow = subnetIndexes.row
		}
		if lastCol < subnetIndexes.col {
			lastCol = subnetIndexes.col
		}
	}
	nSubnets := 0
	for r := firstRow; r <= lastRow; r++ {
		for c := firstCol; c <= lastCol; c++ {
			subnet := ly.subnetMatrix[r][c]
			if subnet != nil && subnet != fakeSubnet {
				if !group.subnets[subnet] {
					return false
				}
				nSubnets++
			}
		}
	}

	return nSubnets == len(group.subnets)
}
