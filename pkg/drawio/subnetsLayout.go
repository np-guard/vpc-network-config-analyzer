package drawio

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// //////////////////////////////////////////////////////////////////////////////////////////////
var interfaceIndex map[interface{}]int

type setAsKey string

func asKey(l []interface{}) setAsKey {
	if interfaceIndex == nil {
		interfaceIndex = map[interface{}]int{}
	}
	ss := []string{}
	for _, i := range l {
		if _, ok := interfaceIndex[i]; !ok {
			interfaceIndex[i] = len(interfaceIndex)
		}
		ss = append(ss, strconv.Itoa(interfaceIndex[i]))
	}
	sort.Strings(ss)
	return setAsKey(strings.Join(ss, ","))
}

type squareSet map[TreeNodeInterface]bool

func (sqs *squareSet) asKey() setAsKey {
	l := []interface{}{}
	for i := range *sqs {
		l = append(l, i)
	}
	return asKey(l)
}

type groupSet map[*groupDataS]bool

func (sqs *groupSet) asKey() setAsKey {
	l := []interface{}{}
	for i := range *sqs {
		l = append(l, i)
	}
	return asKey(l)
}

type miniGroupDataS struct {
	subnets squareSet
	zone    TreeNodeInterface
	located bool
	x, y    int
}
type groupDataS struct {
	miniGroups        map[*miniGroupDataS]bool
	topInnerGroups    []*groupDataS
	toSplitGroups     map[*groupDataS]bool
	subnets           squareSet
	treeNode          TreeNodeInterface
	name              string
	firstRow, lastRow int
	firstCol, lastCol int
	splitFrom         []*groupDataS
	splitTo           []*groupDataS
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
	topFakeGroup := &groupDataS{miniGroups: ly.miniGroups}
	ly.splitSharing(topFakeGroup)
	ly.createNewGroups()
	ly.calcZoneOrder()
	ly.createMatrix()
	ly.layoutGroup(topFakeGroup, 0)
	ly.setSubnetsMatrix()
	ly.checkIntegrity()
	return ly.subnetMatrix, ly.zonesCol
}

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

func isGroupInGroup(subGroup, group *groupDataS) bool {
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

func (ly *subnetsLayout) checkIntegrity() {
	type cell struct {
		subnet TreeNodeInterface
		groups map[*groupDataS]bool
	}
	matrix := make([][]cell, 100)
	for i := range matrix {
		matrix[i] = make([]cell, 100)
		for j := range matrix[i] {
			matrix[i][j].groups = map[*groupDataS]bool{}
		}
	}
	for s, is := range ly.subnetsIndexes {
		matrix[is.row][is.col].subnet = s
	}
	for _, group := range ly.groups {
		if len(group.splitTo) > 0 {
			continue
		}
		group.firstRow, group.firstCol, group.lastRow, group.lastCol = 100, 100, -1, -1
		for subnet := range group.subnets {
			is := ly.subnetsIndexes[subnet]
			c := matrix[is.row][is.col]
			c.groups[group] = true
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
		for r := group.firstRow; r <= group.lastRow; r++ {
			for c := group.firstCol; c <= group.lastCol; c++ {
				subnet := matrix[r][c].subnet
				if subnet != nil {
					if !group.subnets[subnet] {
						fmt.Printf("subnet %s not in group %s\n", subnet.Label(), group.name)
					}
				}
				matrix[r][c].groups[group] = true
			}
		}
	}
	for ri, row := range matrix {
		for ci, cell := range row {
			if cell.subnet == nil && len(cell.groups) > 0 {
				ly.subnetMatrix[ri][ci] = ly.network
			}
		}
	}
}

func (ly *subnetsLayout) getInnerGroups(group *groupDataS) []*groupDataS {
	allInnerGroups := []*groupDataS{}
	for _, group1 := range ly.groups {
		if group1 != group && isGroupInGroup(group1, group) {
			allInnerGroups = append(allInnerGroups, group1)
		}
	}
	return allInnerGroups
}

// ////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) splitSharing(group *groupDataS) {

	group.toSplitGroups = map[*groupDataS]bool{}
	nonSplitGroup := map[*groupDataS]bool{}
	ly.getInnerGroups(group)
	for _, innerGroup := range ly.getInnerGroups(group) {
		if len(innerGroup.splitTo) == 0 {
			nonSplitGroup[innerGroup] = true
		}
	}
	for {
		innerGroups := map[*groupDataS]bool{}
		for group1 := range nonSplitGroup {
			for group2 := range nonSplitGroup {
				if group1 != group2 && isGroupInGroup(group1, group2) {
					innerGroups[group1] = true
				}
			}
		}

		sharedMini := map[*groupDataS]map[*groupDataS]bool{}

		for group1 := range nonSplitGroup {
			for group2 := range nonSplitGroup {
				if group1 != group2 {
					if !innerGroups[group1] && !innerGroups[group2] && isShareMiniGroup(group1, group2) {
						if _, ok := sharedMini[group1]; !ok {
							sharedMini[group1] = map[*groupDataS]bool{}
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
			fmt.Println("group created ", name, " ", string(groups))
			newGroup = &groupDataS{miniGroups: miniGroups, name: name}
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
				splitGroup.splitTo = append(splitGroup.splitTo, newGroup)
				newGroup.splitFrom = append(newGroup.splitFrom, splitGroup)
			}
		}
	}
}
func getVpc(group *groupDataS) *VpcTreeNode {
	if group.treeNode != nil {
		return group.treeNode.Parent().(*VpcTreeNode)
	}
	return getVpc(group.splitFrom[0])
}

// //////////////////////////////////////////
func (ly *subnetsLayout) createNewGroups() {
	tnToSplit := map[TreeNodeInterface]*groupDataS{}
	for _, group := range ly.groups {
		if len(group.splitTo) != 0 && group.treeNode != nil {
			group.treeNode.SetNotShownInDrawio()
			tnToSplit[group.treeNode] = group
		}
	}

	for _, group := range ly.groups {
		if len(group.splitTo) == 0 && group.treeNode == nil {
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
			for _, gr := range srcGroup.splitTo {
				allSrcs = append(allSrcs, gr.treeNode)
			}
		}
		if dstGroup != nil {
			allDsts = []TreeNodeInterface{}
			for _, gr := range dstGroup.splitTo {
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
		groupData := groupDataS{treeNode: groupTn, subnets: groupSubnets[groupTn], name: groupTn.Label(), miniGroups: miniGroups}
		ly.groups = append(ly.groups, &groupData)
	}
	sort.Slice(ly.groups, func(i, j int) bool {
		return len(ly.groups[i].miniGroups) > len(ly.groups[j].miniGroups)
	})
}

//////////////////////////////////////////////////////////////////////////
