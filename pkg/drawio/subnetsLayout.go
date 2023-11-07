package drawio

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// //////////////////////////////////////////////////////////////////////////////////////////////
var tnIndexes map[TreeNodeInterface]int

type squareSet map[TreeNodeInterface]bool
type squareSetAsKey string

func (sqs *squareSet) asKey() squareSetAsKey {
	if tnIndexes == nil {
		tnIndexes = map[TreeNodeInterface]int{}
	}
	ss := []string{}
	for tn := range *sqs {
		if _, ok := tnIndexes[tn]; !ok {
			tnIndexes[tn] = len(tnIndexes)
		}
		ss = append(ss, strconv.Itoa(tnIndexes[tn]))
	}
	sort.Strings(ss)
	key := squareSetAsKey(strings.Join(ss, ","))
	fmt.Println(key)
	return key
}

type miniGroupDataS struct {
	subnets squareSet
	zone    TreeNodeInterface
	groups  []*groupDataS
	located bool
	x, y    int
}
type groupDataS struct {
	miniGroups        []*miniGroupDataS
	allInnerGroups    []*groupDataS
	topInnerGroups    []*groupDataS
	toSplitGroups     map[*groupDataS]bool
	subnets           squareSet
	treeNode          TreeNodeInterface
	name              string
	located           bool
	firstRow, lastRow int
	firstCol, lastCol int
}

// ////////////////////////////////////////////////////////////////////////
type indexes struct {
	row, col int
}
type subnetsLayout struct {
	groups           []*groupDataS
	miniGroups       []*miniGroupDataS
	miniGroupsMatrix [][]*miniGroupDataS
	subnetMatrix     [][]TreeNodeInterface
	subnetsIndexes   map[TreeNodeInterface]indexes
	zoneOrder        []TreeNodeInterface
	zonesCol         map[TreeNodeInterface]int
}

func (ly *subnetsLayout) layout(grs []*GroupSubnetsSquareTreeNode) ([][]TreeNodeInterface, map[TreeNodeInterface]int) {
	ly.createMiniGroups(grs)
	ly.setInnerGroups()
	topFakeGroup := &groupDataS{allInnerGroups: ly.groups, miniGroups: ly.miniGroups}
	splitSharing(topFakeGroup)
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

func groupInGroup(gr1, gr2 *groupDataS) bool {
	minis := map[*miniGroupDataS]bool{}
	for _, mg := range gr2.miniGroups {
		minis[mg] = true
	}
	for _, mg := range gr1.miniGroups {
		if !minis[mg] {
			return false
		}
	}
	return true
}

func shareMiniGroup(gr1, gr2 *groupDataS) bool {
	minis := map[*miniGroupDataS]bool{}
	for _, mg := range gr2.miniGroups {
		minis[mg] = true
	}
	for _, mg := range gr1.miniGroups {
		if minis[mg] {
			return true
		}
	}
	return false
}

func (ly *subnetsLayout) canShareRow(gr1, gr2 *groupDataS) bool {
	miniGroups1 := map[*miniGroupDataS]bool{}
	miniGroups2 := map[*miniGroupDataS]bool{}
	for _, mg := range gr1.miniGroups {
		miniGroups1[mg] = true
	}
	for _, mg := range gr2.miniGroups {
		miniGroups2[mg] = true
	}

	minSepZone1, minSepZone2 := 1000, 1000
	maxSepZone1, maxSepZone2 := -1, -1
	for mg := range miniGroups1 {
		if !miniGroups2[mg] {
			if minSepZone1 > ly.zonesCol[mg.zone] {
				minSepZone1 = ly.zonesCol[mg.zone]
			}
			if maxSepZone1 < ly.zonesCol[mg.zone] {
				maxSepZone1 = ly.zonesCol[mg.zone]
			}
		}
	}
	for mg := range miniGroups2 {
		if !miniGroups1[mg] {
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
	for _, miniGroup := range group.miniGroups {
		if miniGroup.located {
			continue
		}
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
	ly.subnetsIndexes = map[TreeNodeInterface]indexes{}

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
				ly.subnetMatrix[ri][ci] = ly.miniGroups[0].zone
			}
		}
	}
}

func (ly *subnetsLayout) setInnerGroups() {
	for _, group1 := range ly.groups {
		for _, group2 := range ly.groups {
			if group1 != group2 && groupInGroup(group1, group2) {
				group2.allInnerGroups = append(group2.allInnerGroups, group1)
			}
		}
	}
}

// ////////////////////////////////////////////////////////////////////////
func splitSharing(group *groupDataS) {
	nonSplitGroup := map[*groupDataS]bool{}
	for _, innerGroup := range group.allInnerGroups {
		nonSplitGroup[innerGroup] = true
	}
	for {
		innerGroups := map[*groupDataS]bool{}
		for group1 := range nonSplitGroup {
			for group2 := range nonSplitGroup {
				if group1 != group2 && groupInGroup(group1, group2) {
					innerGroups[group1] = true
				}
			}
		}

		sharedMini := map[*groupDataS]map[*groupDataS]bool{}

		for group1 := range nonSplitGroup {
			for group2 := range nonSplitGroup {
				if group1 != group2 {
					if !innerGroups[group1] && !innerGroups[group2] && shareMiniGroup(group1, group2) {
						if _, ok := sharedMini[group1]; !ok {
							sharedMini[group1] = map[*groupDataS]bool{}
						}
						sharedMini[group1][group2] = true
					}
				}
			}
		}
		group.toSplitGroups = map[*groupDataS]bool{}
		bestSharingScore := 0
		var mostSharedGroup *groupDataS
		for sharedGroup, sharedGroups := range sharedMini {
			if len(sharedGroups) > bestSharingScore ||
				(len(sharedGroups) == bestSharingScore && len(sharedGroup.allInnerGroups) < len(mostSharedGroup.allInnerGroups)) {
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
	for _, topInnerGroup := range group.topInnerGroups {
		splitSharing(topInnerGroup)

	}
}

// ////////////////////////////////////////////////////////////////////////
func (ly *subnetsLayout) calcZoneOrder() {
	zoneConnections := map[TreeNodeInterface]map[TreeNodeInterface]int{}
	for _, group := range ly.groups {
		for _, miniGroup1 := range group.miniGroups {
			for _, miniGroup2 := range group.miniGroups {
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
	ly.zoneOrder = zoneOrder
	ly.zonesCol = map[TreeNodeInterface]int{}
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
	fmt.Println("subnetToGroups: ")
	groupSetToMiniGroup := map[squareSetAsKey]map[TreeNodeInterface]squareSet{}
	for subnet, groups := range subnetToGroups {
		if _, ok := groupSetToMiniGroup[groups.asKey()]; !ok {
			groupSetToMiniGroup[groups.asKey()] = map[TreeNodeInterface]squareSet{}
		}
		if _, ok := groupSetToMiniGroup[groups.asKey()][subnet.Parent()]; !ok {
			groupSetToMiniGroup[groups.asKey()][subnet.Parent()] = squareSet{}
		}
		groupSetToMiniGroup[groups.asKey()][subnet.Parent()][subnet] = true
	}
	groupToMiniGroups := map[TreeNodeInterface][]*miniGroupDataS{}
	miniGroups := []*miniGroupDataS{}
	for _, zoneMiniGroup := range groupSetToMiniGroup {
		for zone, miniGroup := range zoneMiniGroup {
			miniGroupData := miniGroupDataS{subnets: miniGroup, zone: zone}
			miniGroups = append(miniGroups, &miniGroupData)
			for subnet := range miniGroup {
				for group := range subnetToGroups[subnet] {
					groupToMiniGroups[group] = append(groupToMiniGroups[group], &miniGroupData)
				}
			}

		}
	}
	groups := []*groupDataS{}
	for group, miniGroups2 := range groupToMiniGroups {
		groupData := groupDataS{treeNode: group, subnets: groupSubnets[group], name: group.Label()}
		groups = append(groups, &groupData)
		for _, miniGroup := range miniGroups2 {
			groupData.miniGroups = append(groupData.miniGroups, miniGroup)
			miniGroup.groups = append(miniGroup.groups, &groupData)
		}
	}

	sort.Slice(miniGroups, func(i, j int) bool {
		return len(miniGroups[i].groups) > len(miniGroups[j].groups)
	})
	for _, miniGroup := range miniGroups {
		sort.Slice(miniGroup.groups, func(i, j int) bool {
			return len(miniGroup.groups[i].miniGroups) > len(miniGroup.groups[j].miniGroups)
		})
	}
	sort.Slice(groups, func(i, j int) bool {
		return len(groups[i].miniGroups) > len(groups[j].miniGroups)
	})
	ly.groups = groups
	ly.miniGroups = miniGroups
}

//////////////////////////////////////////////////////////////////////////
