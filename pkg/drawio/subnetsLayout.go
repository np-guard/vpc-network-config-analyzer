package drawio

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// //////////////////////////////////////////////////////////////////////////////////////////////

type setAsKey string
type squareSet map[TreeNodeInterface]bool
type groupSet map[*groupDataS]bool

var interfaceIndex map[interface{}]int
func asKey(s map[interface{}]bool) setAsKey {
	if interfaceIndex == nil {
		interfaceIndex = map[interface{}]int{}
	}
	ss := []string{}
	for i := range s {
		if _, ok := interfaceIndex[i]; !ok {
			interfaceIndex[i] = len(interfaceIndex)
		}
		ss = append(ss, strconv.Itoa(interfaceIndex[i]))
	}
	sort.Strings(ss)
	return setAsKey(strings.Join(ss, ","))
}
func (sqs *squareSet) asKey() setAsKey {
	s := map[interface{}]bool{}
	for i := range *sqs {
		s[i] = true
	}
	return asKey(s)
}
func (sqs *groupSet) asKey() setAsKey {
	s := map[interface{}]bool{}
	for i := range *sqs {
		s[i] = true
	}
	return asKey(s)
}

/////////////////////////////////////////////////////////////////////////////////////////////////////

type miniGroupDataS struct {
	subnets squareSet
	zone    TreeNodeInterface
	located bool
}
type groupDataS struct {
	miniGroups        map[*miniGroupDataS]bool
	topInnerGroups    []*groupDataS
	toSplitGroups     groupSet
	subnets           squareSet
	treeNode          TreeNodeInterface
	name              string
	firstRow, lastRow int
	firstCol, lastCol int
	splitFrom         groupSet
	splitTo           groupSet
}

func newGroupDataS(name string, miniGroups map[*miniGroupDataS]bool, subnets squareSet, tn TreeNodeInterface) *groupDataS {
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
	miniGroups       map[*miniGroupDataS]bool
	miniGroupsMatrix [][]*miniGroupDataS
	subnetMatrix     [][]TreeNodeInterface
	subnetsIndexes   map[TreeNodeInterface]indexes
	zonesCol         map[TreeNodeInterface]int
}

func newSubnetsLayout(network SquareTreeNodeInterface) *subnetsLayout {
	return &subnetsLayout{
		network:        network,
		miniGroups:     map[*miniGroupDataS]bool{},
		subnetsIndexes: map[TreeNodeInterface]indexes{},
		zonesCol:       map[TreeNodeInterface]int{},
	}
}

func (ly *subnetsLayout) layout(grs []*GroupSubnetsSquareTreeNode) ([][]TreeNodeInterface, map[TreeNodeInterface]int) {
	ly.createMiniGroups(grs)
	topFakeGroup := newGroupDataS("", ly.miniGroups, nil, nil)
	ly.splitSharing(topFakeGroup)
	ly.calcZoneOrder()
	ly.createMatrix()
	ly.layoutGroup(topFakeGroup, 0)
	ly.setSubnetsMatrix()
	ly.setGroupsIndexes()
	ly.createNewGroups()
	ly.fillGroupsSquares()
	// ly.checkIntegrity()
	return ly.subnetMatrix, ly.zonesCol
}
/////////////////////////////////////////////////////////////////////////////////////

func (ly *subnetsLayout) createMatrix() {
	yDim := 100
	xDim := 100

	ly.miniGroupsMatrix = make([][]*miniGroupDataS, yDim)
	for i := range ly.miniGroupsMatrix {
		ly.miniGroupsMatrix[i] = make([]*miniGroupDataS, xDim)
	}

	ly.subnetMatrix = make([][]TreeNodeInterface, yDim)
	for i := range ly.miniGroupsMatrix {
		ly.subnetMatrix[i] = make([]TreeNodeInterface, xDim)
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
func isSameMinisSlice(minis1, minis2 map[*miniGroupDataS]bool) bool {
	if len(minis2) != len(minis1) {
		return false
	}
	for mg := range minis1 {
		if !minis2[mg] {
			return false
		}
	}
	return true
}

func isShareMiniGroup(gr1, gr2 *groupDataS) bool {
	for mg := range gr1.miniGroups {
		if gr2.miniGroups[mg] {
			return true
		}
	}
	return false
}

func (ly *subnetsLayout) canShareRow(gr1, gr2 *groupDataS) bool {
	minSepZone1, minSepZone2 := 1000, 1000
	maxSepZone1, maxSepZone2 := -1, -1
	for mg := range gr1.miniGroups {
		if !gr2.miniGroups[mg] {
			if minSepZone1 > ly.zonesCol[mg.zone] {
				minSepZone1 = ly.zonesCol[mg.zone]
			}
			if maxSepZone1 < ly.zonesCol[mg.zone] {
				maxSepZone1 = ly.zonesCol[mg.zone]
			}
		}
	}
	for mg := range gr2.miniGroups {
		if !gr1.miniGroups[mg] {
			if minSepZone2 > ly.zonesCol[mg.zone] {
				minSepZone2 = ly.zonesCol[mg.zone]
			}
			if maxSepZone2 < ly.zonesCol[mg.zone] {
				maxSepZone2 = ly.zonesCol[mg.zone]
			}
		}
	}
	if maxSepZone1 == -1 || maxSepZone2 == -1 {
		return true
	}
	if minSepZone1 > maxSepZone2 {
		return true
	}
	if minSepZone2 > maxSepZone1 {
		return true
	}
	return false
}

// ////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) layoutGroup(group *groupDataS, firstRow int) int {
	rowIndex := firstRow
	lastRow := firstRow
	maxRowSize := 0
	fmt.Println("layout group ", group.name)
	for i, innerGroup := range group.topInnerGroups {
		newRowSize := ly.layoutGroup(innerGroup, rowIndex)
		if newRowSize > maxRowSize {
			maxRowSize = newRowSize
		}
		if i < len(group.topInnerGroups)-1 && !ly.canShareRow(innerGroup, group.topInnerGroups[i+1]) {
			rowIndex += maxRowSize
			maxRowSize = 0
		}
		lastRow = rowIndex + maxRowSize
	}
	for miniGroup := range group.miniGroups {
		if miniGroup.located {
			continue
		}
		name := ""
		for s := range miniGroup.subnets {
			name += s.Label() + ","
		}
		fmt.Println("layout mini:  ", name)
		i := 0
		for ly.miniGroupsMatrix[firstRow+i][ly.zonesCol[miniGroup.zone]] != nil {
			i++
		}
		if lastRow < firstRow+i {
			lastRow = firstRow + i
		}
		ly.miniGroupsMatrix[firstRow+i][ly.zonesCol[miniGroup.zone]] = miniGroup
		miniGroup.located = true
	}
	fmt.Println("end layout group ", group.name)
	return lastRow - firstRow + 1

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
			is := ly.subnetsIndexes[subnet]
			if group.firstRow > is.row {
				group.firstRow = is.row
			}
			if group.firstCol > is.col {
				group.firstCol = is.col
			}
			if group.lastRow < is.row {
				group.lastRow = is.row
			}
			if group.lastCol < is.col {
				group.lastCol = is.col
			}
		}
	}
}

func (ly *subnetsLayout) getInnerGroups(group *groupDataS) []*groupDataS {
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
	for _, innerGroup := range ly.getInnerGroups(group) {
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
					if !innerGroups[group1] && !innerGroups[group2] && isShareMiniGroup(group1, group2) {
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

// /////////////////////////////////////////////////
func (ly *subnetsLayout) rearrangeGroup(group *groupDataS) {
	splitMiniGroups := map[*miniGroupDataS]bool{}
	for splitGroup := range group.toSplitGroups {
		for mn := range splitGroup.miniGroups {
			splitMiniGroups[mn] = true
		}
	}
	miniGroupToGroupSet := map[*miniGroupDataS]groupSet{}
	for _, group := range ly.getInnerGroups(group) {
		for miniGroup := range group.miniGroups {
			if splitMiniGroups[miniGroup] {
				if _, ok := miniGroupToGroupSet[miniGroup]; !ok {
					miniGroupToGroupSet[miniGroup] = groupSet{}
				}
				miniGroupToGroupSet[miniGroup][group] = true
			}
		}
	}
	groupSetToNewGroups := map[setAsKey]map[*miniGroupDataS]bool{}
	keysToSet := map[setAsKey]groupSet{}
	for miniGroup, groupSet := range miniGroupToGroupSet {
		if _, ok := groupSetToNewGroups[groupSet.asKey()]; !ok {
			groupSetToNewGroups[groupSet.asKey()] = map[*miniGroupDataS]bool{}
		}
		groupSetToNewGroups[groupSet.asKey()][miniGroup] = true
		keysToSet[groupSet.asKey()] = groupSet
	}
	for groups, miniGroups := range groupSetToNewGroups {
		var newGroup *groupDataS
		for _, gr := range ly.groups {
			if isSameMinisSlice(gr.miniGroups, miniGroups) {
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
			subnets := squareSet{}
			for miniGroup := range group.miniGroups {
				for subnet := range miniGroup.subnets {
					subnets[subnet] = true
				}
			}
			fmt.Println("group created ", name, " ", string(groups))
			newGroup = newGroupDataS(name, miniGroups, subnets, nil)
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
func getVpc(group *groupDataS) *VpcTreeNode {
	if group.treeNode != nil {
		return group.treeNode.Parent().(*VpcTreeNode)
	}
	var a *groupDataS
	for a = range group.splitFrom {
		return getVpc(a)
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
				group.treeNode = GroupedSubnetsSquare(getVpc(group), subnets)
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
	for r := group.firstRow; r <= group.lastRow; r++ {
		for c := group.firstCol; c <= group.lastCol; c++ {
			subnet := ly.subnetMatrix[r][c]
			if subnet != nil && !group.subnets[subnet] {
				return false
			}
		}
	}
	return true
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

func (ly *subnetsLayout) createMiniGroups(grs []*GroupSubnetsSquareTreeNode) {
	groupedSubnets := squareSet{}
	groupSubnets := map[TreeNodeInterface]squareSet{}
	for _, group := range grs {
		groupSubnets[group] = squareSet{}
		for _, subnet := range group.groupedSubnets {
			groupSubnets[group][subnet] = true
			groupedSubnets[subnet] = true
		}
	}
	subnetToGroups := map[TreeNodeInterface]squareSet{}
	for subnet := range groupedSubnets {
		subnetToGroups[subnet] = squareSet{}
	}
	for _, group := range grs {
		for _, subnet := range group.groupedSubnets {
			subnetToGroups[subnet][group] = true
		}
	}
	groupSetToMiniGroup := map[setAsKey]map[TreeNodeInterface]squareSet{}
	for subnet, groups := range subnetToGroups {
		if _, ok := groupSetToMiniGroup[groups.asKey()]; !ok {
			groupSetToMiniGroup[groups.asKey()] = map[TreeNodeInterface]squareSet{}
		}
		if _, ok := groupSetToMiniGroup[groups.asKey()][subnet.Parent()]; !ok {
			groupSetToMiniGroup[groups.asKey()][subnet.Parent()] = squareSet{}
		}
		groupSetToMiniGroup[groups.asKey()][subnet.Parent()][subnet] = true
	}
	groupToMiniGroups := map[TreeNodeInterface]map[*miniGroupDataS]bool{}
	for _, zoneMiniGroup := range groupSetToMiniGroup {
		for zone, miniGroup := range zoneMiniGroup {
			miniGroupData := miniGroupDataS{subnets: miniGroup, zone: zone}
			ly.miniGroups[&miniGroupData] = true
			for subnet := range miniGroup {
				for group := range subnetToGroups[subnet] {
					if _, ok := groupToMiniGroups[group]; !ok {
						groupToMiniGroups[group] = map[*miniGroupDataS]bool{}
					}
					groupToMiniGroups[group][&miniGroupData] = true
				}
			}

		}
	}
	for groupTn, miniGroups := range groupToMiniGroups {
		groupData := newGroupDataS(groupTn.Label(), miniGroups, groupSubnets[groupTn], groupTn)
		ly.groups = append(ly.groups, groupData)
	}
	sort.Slice(ly.groups, func(i, j int) bool {
		return len(ly.groups[i].miniGroups) > len(ly.groups[j].miniGroups)
	})
}

//////////////////////////////////////////////////////////////////////////
