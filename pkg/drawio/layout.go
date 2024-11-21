/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

import (
	"maps"
	"slices"
	"sort"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// layoutS is the main struct for layouting the tree nodes
// overview to the layout algorithm:
// the input to the layout algorithm is the tree itself. the output is the geometry for each node in the drawio (x, y, height, width)
// the steps:
// 1. create a 2D matrix  - for each subnet icon, it set the location in the matrix (see details about layouting a subnet)
// (when we are in subnet mode, we set the locations of the subnets, using the subnetsLayout struct. see subnetsLayout.go
// 2. set the locations of the SG in the matrix, according to the locations of the icons
// 3. add squares borders - resizing the matrix. adding rows and columns to the matrix, to be used as the borders of all squares
// 4. set the locations of all the squares in the matrix
// 5. set the locations of all the non subnet icons
// 6. set the geometry for each node in the drawio

// the implementation of the matrix is the layoutMatrix struct.
// layoutMatrix holds a list of column and a list of rows.
// the layoutMatrix does not hold the treeNodes in it.
// instead, each node holds pointers to its rows and columns (square can be in more than one rows/column).
// alongside these pointers, the treNode holds the position inside the Matrix cell ( see struct Location)
// that alow to add/remove rows/column without updating the treeNodes.

const (
	minSize          = 10
	fourTimesMinSize = 40
	borderWidth      = 40
	subnetWidth      = 8 * 40
	subnetHeight     = 6 * 40
	iconSize         = 60
	groupedIconSize  = 10
	iconSpace        = 4 * 40

	groupBorderWidth      = 20
	groupTopBorderWidth   = 60
	groupedIconsDistance  = 30
	groupInnerBorderWidth = 10

	fipXOffset = -70
	fipYOffset = 40

	miniIconXOffset = 30
	miniIconYOffset = -10
	miniIconSize    = 40

	vsiOneRowYOffset   = 90
	vsiMultiRowYOffset = subnetHeight / 2

	// network -> cloud -> region -> vpc -> zone -> subnets
	networkToSubnetDepth = 5
	cloudToSubnetDepth   = 4
	regionToSubnetDepth  = 3
	vpcToSubnetDepth     = 2
	zoneToSubnetDepth    = 1
)

type layoutS struct {
	network    SquareTreeNodeInterface
	matrix     *layoutMatrix
	subnetMode bool
}

func newLayout(network SquareTreeNodeInterface, subnetMode bool) *layoutS {
	return &layoutS{network: network, matrix: newLayoutMatrix(), subnetMode: subnetMode}
}

func (ly *layoutS) layout() {
	// main layout algorithm:
	// 1. create a 2D matrix  - for each subnet icon, it set the location in the matrix
	// in case of subnet mode, set the locations of the subnets
	if !ly.subnetMode {
		ly.layoutSubnetsIcons()
	} else {
		ly.layoutSubnets()
	}
	ly.matrix.removeUnusedLayers()
	// 2. set the locations of the SG in the matrix, according to the locations of the icons
	ly.setSGLocations()
	// 3. add squares borders - resizing the matrix. adding rows and columns to the matrix, to be used as the borders of all squares
	ly.addAllBorderLayers()
	// 4. set the locations of all the squares in the matrix
	ly.setSquaresLocations()
	ly.matrix.removeUnusedLayers()
	// 5. set the locations of all the non-subnet icons
	ly.setIconsLocations()
	// 6. set the geometry for each node in the drawio
	ly.matrix.setLayersDistance()
	ly.setGeometries()
	ly.setRouterPoints()
	if !ly.subnetMode {
		newLayoutOverlap(ly.network).fixOverlapping()
	} else {
		newSubnetLayoutOverlap(ly.network, ly.matrix).fixOverlapping()
	}
}

// setDefaultLocation() set locations to squares
// these locations are relevant only in cases the square has no elements
func (ly *layoutS) setDefaultLocation(tn SquareTreeNodeInterface, rowIndex, colIndex int) {
	l := ly.matrix.allocateCellLocation(rowIndex, colIndex)
	l.firstRow.setHeight(subnetHeight)
	l.firstCol.setWidth(subnetWidth)
	tn.setLocation(l)
}

func canShareCell(i1, i2 IconTreeNodeInterface) bool {
	switch {
	case i1 == nil || i2 == nil:
		return true
	case i1.SGs().AsKey() != i2.SGs().AsKey():
		return false
	case i1.HasFip():
		return false
	case i2.HasFip():
		return false
	}
	return true
}

// sortGroupSquareBySize() sorts a slice of GroupSquareTreeNodes by the size of their groupedIcons set.
func sortGroupSquareBySize(groups []SquareTreeNodeInterface) []SquareTreeNodeInterface {
	sortedBySizeGroups := make([]SquareTreeNodeInterface, len(groups))
	copy(sortedBySizeGroups, groups)
	sort.Slice(sortedBySizeGroups, func(i, j int) bool {
		return len(sortedBySizeGroups[i].(*GroupSquareTreeNode).groupedIcons) > len(sortedBySizeGroups[j].(*GroupSquareTreeNode).groupedIcons)
	})
	return sortedBySizeGroups
}

// layouting a subnet is done in the following steps:
// 1. calcGroupsVisibility()
// 2. getSubnetIconsOrder()
// 3. for each group - layoutGroupIcons()

//  1. calcGroupsVisibility() - for each group set the visibility of the group
//     there are 4 kind of visibility:
//     a. theSubnet - the group is all the NIs in the subnet
//     b. square - the group is a subset of the NIs subnet, the group will be bordered with a square
//     c. innerSquare - the group is a subset of a group of square , the group will be bordered with an inner square inside a square
//     d. connectedPoint - the group can not be bordered, so it is connected with line to a grouping point
//
// the algorithm:
//
//	  we sort the groups by their size, and start with the biggest:
//			for each group:
//			 - if the group contains all the NIs of the subnet - its visibility is theSubnet
//	         - else if all the NIs in the group not in a bigger group - its visibility is square
//	         - else if all the NIs in the group are in one bigger group - its visibility is innerSquare
//	         - else its visibility is connectedPoint
func calcGroupsVisibility(subnet SquareTreeNodeInterface) {
	sortedBySizeGroups := sortGroupSquareBySize(subnet.(*SubnetTreeNode).groupSquares)
	iconShownSquareGroups := map[IconTreeNodeInterface]map[SquareTreeNodeInterface]bool{}
	for _, groupS := range sortedBySizeGroups {
		group := groupS.(*GroupSquareTreeNode)
		groupedIconsFormerGroups := map[SquareTreeNodeInterface]bool{}
		hasIconOutsideAGroup := false
		for _, icon := range group.groupedIcons {
			if len(iconShownSquareGroups[icon]) == 0 {
				hasIconOutsideAGroup = true
			}
			for g := range iconShownSquareGroups[icon] {
				groupedIconsFormerGroups[g] = true
			}
		}
		switch {
		case len(group.groupedIcons) == len(subnet.(*SubnetTreeNode).nonGroupingIcons()):
			group.setVisibility(theSubnet)
		case len(groupedIconsFormerGroups) == 0:
			group.setVisibility(square)
		case len(groupedIconsFormerGroups) == 1 && !hasIconOutsideAGroup:
			group.setVisibility(innerSquare)
		default:
			group.setVisibility(connectedPoint)
		}
		if !group.NotShownInDrawio() {
			for _, icon := range group.groupedIcons {
				if _, ok := iconShownSquareGroups[icon]; !ok {
					iconShownSquareGroups[icon] = map[SquareTreeNodeInterface]bool{}
				}
				iconShownSquareGroups[icon][group] = true
			}
		}
	}
}

// 2. getSubnetIconsOrder() - set the order of the icons to be displayed in the subnet
//   returns [][]IconTreeNodeInterface - the order of the icons.

func getSubnetIconsOrder(subnet SquareTreeNodeInterface) [][]IconTreeNodeInterface {
	sortedBySizeGroups := sortGroupSquareBySize(subnet.(*SubnetTreeNode).groupSquares)
	iconOuterGroup := map[IconTreeNodeInterface]SquareTreeNodeInterface{}
	iconInnerGroup := map[IconTreeNodeInterface]SquareTreeNodeInterface{}
	outerToInnersGroup := map[SquareTreeNodeInterface]map[SquareTreeNodeInterface]bool{}
	// collect for each group with viability square its innerSquares groups:
	for _, groupS := range sortedBySizeGroups {
		group := groupS.(*GroupSquareTreeNode)
		if group.visibility == square {
			outerToInnersGroup[group] = map[SquareTreeNodeInterface]bool{}
			for _, icon := range group.groupedIcons {
				iconOuterGroup[icon] = group
			}
		} else if group.visibility == innerSquare {
			for _, icon := range group.groupedIcons {
				iconInnerGroup[icon] = group
				outerToInnersGroup[iconOuterGroup[icon]][group] = true
			}
		}
	}
	iconsOrder := [][]IconTreeNodeInterface{}
	for outerGroupS, innerGroups := range outerToInnersGroup {
		outerGroup := outerGroupS.(*GroupSquareTreeNode)
		// for each outer group - add its inner group icons:
		for innerGroup := range innerGroups {
			iconsOrder = append(iconsOrder, innerGroup.(*GroupSquareTreeNode).groupedIcons)
		}
		noInnerIcons := []IconTreeNodeInterface{}
		// for each outer group - add the rest of the icons:
		for _, icon := range outerGroup.groupedIcons {
			if _, ok := iconInnerGroup[icon]; !ok {
				noInnerIcons = append(noInnerIcons, icon)
			}
		}
		iconsOrder = append(iconsOrder, noInnerIcons)
	}
	// add the rest of the icons in the subnet
	nonGroupedIcons := []IconTreeNodeInterface{}
	for _, icon := range subnet.(*SubnetTreeNode).nonGroupingIcons() {
		if _, ok := iconOuterGroup[icon]; !ok {
			nonGroupedIcons = append(nonGroupedIcons, icon)
		}
	}
	iconsOrder = append(iconsOrder, nonGroupedIcons)
	return iconsOrder
}

// layoutGroupIcons() - set the location of the icons
// cell can hold at most two icons
// only icons with the same sg and same group and no fip can share a cell
func (ly *layoutS) layoutGroupIcons(group []IconTreeNodeInterface, rowIndex, colIndex int) (nextRowIndex, nextColIndex int) {
	var iconInCurrentCell IconTreeNodeInterface = nil
	for _, icon := range group {
		if !canShareCell(iconInCurrentCell, icon) {
			rowIndex++
			iconInCurrentCell = nil
		}
		if iconInCurrentCell == nil {
			l := ly.matrix.allocateCellLocation(rowIndex, colIndex)
			l.firstRow.setHeight(subnetHeight)
			l.firstCol.setWidth(subnetWidth)
			icon.setLocation(l)
			iconInCurrentCell = icon
		} else {
			icon.setLocation(iconInCurrentCell.Location().copy())
			iconInCurrentCell.Location().xOffset = -iconSize
			icon.Location().xOffset = iconSize
			rowIndex++
			iconInCurrentCell = nil
		}
	}
	if iconInCurrentCell != nil {
		rowIndex++
	}
	nextRowIndex, nextColIndex = rowIndex, colIndex
	return nextRowIndex, nextColIndex
}

// ///////////////////////////////////////////////////////////////
// layoutSubnetsIcons() implements a simple north-south east-west layouting:
// 1. vpcs are next to each others
// 2. zones are next to each others
// 3. subnets a above/below each other
func (ly *layoutS) layoutSubnetsIcons() {
	ly.setDefaultLocation(ly.network, 0, 0)
	colIndex := 0
	for _, cloud := range ly.network.(*NetworkTreeNode).clouds {
		ly.setDefaultLocation(cloud, 0, colIndex)
		for _, region := range cloud.(*CloudTreeNode).regions {
			ly.setDefaultLocation(region, 0, colIndex)
			for _, vpc := range region.(*RegionTreeNode).vpcs {
				ly.setDefaultLocation(vpc, 0, colIndex)
				for _, zone := range vpc.(*VpcTreeNode).zones {
					rowIndex := 0
					ly.setDefaultLocation(zone, rowIndex, colIndex)
					for _, subnet := range zone.(*ZoneTreeNode).subnets {
						ly.setDefaultLocation(subnet, rowIndex, colIndex)
						calcGroupsVisibility(subnet)
						groups := getSubnetIconsOrder(subnet)
						for _, group := range groups {
							rowIndex, colIndex = ly.layoutGroupIcons(group, rowIndex, colIndex)
						}
						if rowIndex == subnet.Location().firstRow.index {
							rowIndex++
						}
					}
					colIndex++
				}
				if vpc.(*VpcTreeNode).zones == nil {
					colIndex++
				}
			}
			if region.(*RegionTreeNode).vpcs == nil {
				colIndex++
			}
		}
		if cloud.(*CloudTreeNode).regions == nil {
			colIndex++
		}
	}
}

func (ly *layoutS) layoutSubnets() {
	sly := newSubnetsLayout(ly.network)
	sly.layout()
	for ri, row := range sly.squaresMatrix {
		for ci, s := range row {
			if s != nil {
				ly.setDefaultLocation(s.(SquareTreeNodeInterface), ri, ci)
			}
		}
	}
}

////////////////////////////////////////////////////////////////////
// resolveGroupedSubnetsOverlap() handles overlapping GroupSubnetsSquare.
// it makes sure that the borders of two squares will not overlap each other.
// the borders of two squares overlap if these two condition happened:
// 1. they share a col and have the same first/last raw, or share a row and have the same first/last col
// 2. they have the same xOffset (since xOffset == yOffset == xEndOffset == yEndOffset)
//
// in case we find such a pair, we shrink the smaller one by increasing its offsets
// we continue to look for such pairs till cant find any

func (ly *layoutS) resolveGroupedSubnetsOverlap() {
	allSubnetsSquares := map[*GroupSubnetsSquareTreeNode]bool{}
	for _, tn := range getAllSquares(ly.network) {
		if !tn.NotShownInDrawio() && tn.IsGroupSubnetsSquare() {
			allSubnetsSquares[tn.(*GroupSubnetsSquareTreeNode)] = true
		}
	}
	for foundOverlap := true; foundOverlap; {
		foundOverlap = false
		for tn1 := range allSubnetsSquares {
			for tn2 := range allSubnetsSquares {
				if tn1 == tn2 {
					continue
				}
				l1 := tn1.Location()
				l2 := tn2.Location()
				if squareBordersOverlap(tn1.Location(), tn2.Location()) {
					if l1.xOffset == l2.xOffset {
						toShrink := tn1
						if len(tn2.groupedSubnets) < len(tn1.groupedSubnets) {
							toShrink = tn2
						}
						toShrink.Location().xOffset += groupInnerBorderWidth
						toShrink.Location().yOffset += groupInnerBorderWidth
						toShrink.Location().xEndOffset += groupInnerBorderWidth
						toShrink.Location().yEndOffset += groupInnerBorderWidth
						foundOverlap = true
					}
				}
			}
		}
	}
}

// check if two squares: share a col and have the same first/last raw, or share a row and have the same first/last col
func squareBordersOverlap(l1, l2 *Location) bool {
	shareCol := !(l1.firstCol.index > l2.lastCol.index || l2.firstCol.index > l1.lastCol.index)
	shareRow := !(l1.firstRow.index > l2.lastRow.index || l2.firstRow.index > l1.lastRow.index)
	sameRow := l1.firstRow == l2.firstRow || l1.lastRow == l2.lastRow
	sameCol := l1.firstCol == l2.firstCol || l1.lastCol == l2.lastCol
	return shareCol && sameRow || shareRow && sameCol
}

// since we do not have subnet icons, we set the subnets smaller and the GroupSubnetsSquare bigger
func (ly *layoutS) setGroupedSubnetsOffset() {
	for _, tn := range getAllSquares(ly.network) {
		switch {
		case tn.NotShownInDrawio():
		case tn.IsSubnet():
			tn.Location().xOffset = borderWidth
			tn.Location().yOffset = borderWidth
			tn.Location().xEndOffset = borderWidth
			tn.Location().yEndOffset = borderWidth

		case tn.IsGroupSubnetsSquare():
			tn.Location().xOffset = -groupBorderWidth
			tn.Location().yOffset = -groupBorderWidth
			tn.Location().xEndOffset = -groupBorderWidth
			tn.Location().yEndOffset = -groupBorderWidth
		}
	}
	ly.resolveGroupedSubnetsOverlap()
}

// //////////////////////////////////////////////////////////////////////////////////////////
// SG can have more than one squares. so setSGLocations() will add treeNodes of the kind PartialSGTreeNode
// PartialSGTreeNode can not have more than one row. and can have only cell that contains icons that belong to the SG
func (ly *layoutS) setSGLocations() {
	for _, cloud := range ly.network.(*NetworkTreeNode).clouds {
		for _, region := range cloud.(*CloudTreeNode).regions {
			for _, vpc := range region.(*RegionTreeNode).vpcs {
				iconsLists := sortIconsBySGs(vpc.(*VpcTreeNode).sgs)
				for _, icons := range iconsLists {
					sgLocation := mergeLocations(locations(icons))
					sgIconsIndexes := map[[2]int]bool{}
					for _, icon := range icons {
						sgIconsIndexes[[2]int{icon.Location().firstRow.index, icon.Location().firstCol.index}] = true
					}
					for ri := sgLocation.firstRow.index; ri <= sgLocation.lastRow.index; ri++ {
						var currentLocation *Location = nil
						// we run also on the next column index, to create the last PartialSGTreeNode
						for ci := sgLocation.firstCol.index; ci <= sgLocation.lastCol.index+1; ci++ {
							isSGCell := sgIconsIndexes[[2]int{ri, ci}]
							switch {
							case currentLocation == nil && isSGCell:
								currentLocation = newCellLocation(ly.matrix.rows[ri], ly.matrix.cols[ci])
							case currentLocation != nil && isSGCell:
								currentLocation.lastCol = ly.matrix.cols[ci]
							case currentLocation != nil && !isSGCell:
								sgs := icons[0].(IconTreeNodeInterface).SGs().AsList()
								psg := newPartialSGTreeNode(sgs)
								currentLocation.xOffset = borderWidth
								currentLocation.yOffset = borderWidth
								currentLocation.xEndOffset = borderWidth
								currentLocation.yEndOffset = borderWidth

								psg.setLocation(currentLocation)
								currentLocation = nil
							}
						}
					}
				}
			}
		}
	}
}

// sortIconsBySGs() sort all the icons by their SGs
// return a list of lists of icons - all the icons in one list have exactly the same set of sgs
func sortIconsBySGs(sgs []SquareTreeNodeInterface) [][]TreeNodeInterface {
	// get all relevant icons:
	icons := []IconTreeNodeInterface{}
	for _, sg := range sgs {
		icons = append(icons, sg.IconTreeNodes()...)
	}
	// remove duplicates
	icons = common.FromList(icons).AsList()
	// get the icons list for every group of sgs:
	sgsToIcons := map[setAsKey][]TreeNodeInterface{}
	for _, icon := range icons {
		sgsAsKey := icon.SGs().AsKey()
		sgsToIcons[sgsAsKey] = append(sgsToIcons[sgsAsKey], icon)
	}
	// covert to list:
	return slices.Collect(maps.Values(sgsToIcons))
}

// ///////////////////////////////////////////////////////////
// Till this stage, we had only subnets in the matrix. now we want add vpcs/zones/clouds, and the public network.
// Between two subnets, there can be one layer one case, and seven in another (subnet<->zone<->vpc<->cloud<->cloud<->vpc<->zone<->subnet)
// First we add layers to all possible borders + 2 cols for public network.
// then we mark all the layers that has are needed.
// then we remove the layers that we do not need
func (ly *layoutS) addAllBorderLayers() {
	newIndexFunction := func(index int) int { return 2 + networkToSubnetDepth + networkToSubnetDepth*2*index }
	ly.matrix.resize(newIndexFunction)
}

func (ly *layoutS) resolvePublicNetworkLocations() {
	pn := ly.network.(*NetworkTreeNode).publicNetwork
	if pn == nil || len(pn.IconTreeNodes()) == 0 {
		return
	}
	allCloudsLocation := mergeLocations(locations(getAllNodes(ly.network)))
	pnl := newLocation(allCloudsLocation.firstRow, allCloudsLocation.lastRow, ly.matrix.cols[1], ly.matrix.cols[1])
	pnl.firstCol.setWidth(iconSpace)
	ly.network.(*NetworkTreeNode).publicNetwork.setLocation(pnl)
}

func setGroupSquareOffsets(tn SquareTreeNodeInterface) {
	if tn.(*GroupSquareTreeNode).visibility == square {
		tn.Location().xOffset = groupBorderWidth
		tn.Location().yOffset = groupTopBorderWidth
		tn.Location().xEndOffset = groupBorderWidth
		tn.Location().yEndOffset = groupBorderWidth
	}
	if tn.(*GroupSquareTreeNode).visibility == innerSquare {
		tn.Location().xOffset = groupBorderWidth + groupInnerBorderWidth
		tn.Location().yOffset = groupTopBorderWidth + groupInnerBorderWidth
		tn.Location().xEndOffset = groupBorderWidth + groupInnerBorderWidth
		tn.Location().yEndOffset = groupBorderWidth + groupInnerBorderWidth
	}
}

func resolveSquareLocation(tn SquareTreeNodeInterface, internalBorders int, addExternalBorders bool) {
	nl := mergeLocations(locations(getAllNodes(tn)))
	for i := 0; i < internalBorders; i++ {
		nl = newLocation(nl.prevRow(), nl.nextRow(), nl.prevCol(), nl.nextCol())
	}
	if internalBorders > 0 {
		nl.firstRow.setHeight(borderWidth)
		nl.lastRow.setHeight(borderWidth)
		nl.firstCol.setWidth(borderWidth)
		nl.lastCol.setWidth(borderWidth)
	}
	if addExternalBorders {
		nl.prevRow().setHeight(borderWidth)
		nl.prevCol().setWidth(borderWidth)
	}
	tn.setLocation(nl)
}

func (ly *layoutS) setSquaresLocations() {
	for _, cloud := range ly.network.(*NetworkTreeNode).clouds {
		resolveSquareLocation(cloud, cloudToSubnetDepth, true)
		for _, region := range cloud.(*CloudTreeNode).regions {
			resolveSquareLocation(region, regionToSubnetDepth, true)
			for _, vpc := range region.(*RegionTreeNode).vpcs {
				resolveSquareLocation(vpc, vpcToSubnetDepth, true)
				for _, zone := range vpc.(*VpcTreeNode).zones {
					resolveSquareLocation(zone, zoneToSubnetDepth, true)
					for _, subnet := range zone.(*ZoneTreeNode).subnets {
						resolveSquareLocation(subnet, 0, true)
						for _, groupSquare := range subnet.(*SubnetTreeNode).groupSquares {
							resolveSquareLocation(groupSquare, 0, false)
							setGroupSquareOffsets(groupSquare)
						}
					}
				}
				for _, groupSubnetsSquare := range vpc.(*VpcTreeNode).groupSubnetsSquares {
					resolveSquareLocation(groupSubnetsSquare, 0, false)
				}
			}
		}
	}
	ly.resolvePublicNetworkLocations()
	resolveSquareLocation(ly.network, 1, false)
	if ly.subnetMode {
		ly.setGroupedSubnetsOffset()
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////
// setPublicNetworkIconsLocations() sets all the icons in the first col.
// choose the rows with heights >= iconSpace, and the rows next to them
func (ly *layoutS) setPublicNetworkIconsLocations() {
	pn := ly.network.(*NetworkTreeNode).publicNetwork
	if pn == nil {
		return
	}
	icons := pn.IconTreeNodes()
	if len(icons) == 0 {
		return
	}
	rows := []*row{}
	for ri, row := range ly.matrix.rows {
		if row.height() >= iconSpace {
			rows = append(rows, row)
			if nextRow := ly.matrix.rows[ri+1]; nextRow.height() < iconSpace {
				rows = append(rows, nextRow)
			}
		}
	}
	iconsPerRow := (len(icons)-1)/len(rows) + 1
	pn.Location().firstCol.setWidth(iconSpace * iconsPerRow)
	for iconIndex, icon := range icons {
		icon.setLocation(newCellLocation(rows[iconIndex/iconsPerRow], pn.Location().firstCol))
		icon.Location().xOffset = iconSpace*(iconIndex%iconsPerRow) - (iconSpace*(iconsPerRow-1))/2
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////
// setIconsLocationsOnTop() sets all the icons in the first square row.
// choose the cols with width >= iconSpace, and the cols next to them
// for icons in vpc
func (ly *layoutS) setIconsLocationsOnTop(square SquareTreeNodeInterface) {
	icons := square.IconTreeNodes()
	if len(icons) == 0 {
		return
	}

	cols := []*col{}
	firstColIndex := square.Location().firstCol.index
	lastColIndex := square.Location().lastCol.index
	for ci := firstColIndex; ci <= lastColIndex; ci++ {
		col := ly.matrix.cols[ci]
		if col.width() >= iconSpace {
			cols = append(cols, col)
			if nextCol := ly.matrix.cols[ci+1]; nextCol.width() < iconSpace {
				cols = append(cols, nextCol)
			}
		}
	}
	iconsPerCol := (len(icons)-1)/len(cols) + 1
	if square.Location().firstRow.height() < iconSpace*iconsPerCol {
		square.Location().firstRow.setHeight(iconSpace * iconsPerCol)
	}
	for iconIndex, icon := range icons {
		icon.setLocation(newCellLocation(square.Location().firstRow, cols[iconIndex/iconsPerCol]))
		icon.Location().yOffset = iconSpace*(iconIndex%iconsPerCol) - (iconSpace*(iconsPerCol-1))/2
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////
// setTgwLocations() sets all the tgw in the first cloud row.
// we assume that number of tgws is less than number of vpcs, so we have enough cols
// we choose the cols with width >= iconSpace. and set a col per tgw (a col can not have two tgw):
// 1. for each tgw, find the optional cols for it (details on optional col below)
// 2. sort the tgws by the number of optional cols (to handle the tgw with the less number of optional cols first)
// 3. for each tgw choose a col from its optional cols
// 4. for those how fail in step 3, choose an closest available col
//
// in general, a col is *not* an optional for a tgw, if there is a line that:
//        a. routers by the tgw
//        b. both src and dst are on the left/right to the col.

func (ly *layoutS) setTgwLocations(region SquareTreeNodeInterface) {
	tgws := slices.Clone(region.IconTreeNodes())
	if len(tgws) == 0 {
		return
	}
	tgwOptionalCols, availableCols := ly.calcTgwOptionalCols(region)
	region.Location().firstRow.setHeight(iconSpace)
	// we want to choose for the tgw with less options:
	sort.Slice(tgws, func(i, j int) bool {
		return len(tgwOptionalCols[tgws[i]]) < len(tgwOptionalCols[tgws[j]])
	})
	for _, tgw := range tgws {
		// the tgwOptionalCols are already sorted, the first and last are our last choice, so moving the first to the end:
		tgwOptionalCols[tgw] = append(tgwOptionalCols[tgw][1:], tgwOptionalCols[tgw][0])
		for _, ci := range tgwOptionalCols[tgw] {
			if availableCols[ci] {
				tgw.setLocation(newCellLocation(region.Location().firstRow, ly.matrix.cols[ci]))
				delete(availableCols, ci)
				break
			}
		}
	}
	for _, tgw := range tgws {
		if tgw.Location() != nil {
			continue
		}
		// hope we do not get here, taking the closest available:
		bestColAvailable, _ := common.AnyMapEntry[int](availableCols)
		bestDistance := region.Location().lastCol.index
		if len(tgwOptionalCols[tgw]) > 0 {
			tgwOptCol := tgwOptionalCols[tgw][0] + tgwOptionalCols[tgw][len(tgwOptionalCols[tgw])-1]/2
			for col := range availableCols {
				if abs(col-tgwOptCol) < bestDistance {
					bestColAvailable = col
					bestDistance = abs(col - tgwOptCol)
				}
			}
		}
		tgw.setLocation(newCellLocation(region.Location().firstRow, ly.matrix.cols[bestColAvailable]))
		delete(availableCols, bestColAvailable)
	}
}

// calcTgwOptionalCols() calc the optional cols of the tgws, and a se of all the cols
func (ly *layoutS) calcTgwOptionalCols(cloud SquareTreeNodeInterface) (
	tgwOptionalCols map[IconTreeNodeInterface][]int, allCols map[int]bool) {
	tgws := cloud.IconTreeNodes()
	firstColIndex, lastColIndex := cloud.Location().firstCol.index, cloud.Location().lastCol.index
	tgwMinCol := map[IconTreeNodeInterface]int{}
	tgwMaxCol := map[IconTreeNodeInterface]int{}
	tgwOptionalCols = map[IconTreeNodeInterface][]int{}
	for _, tgw := range tgws {
		tgwMinCol[tgw] = firstColIndex
		tgwMaxCol[tgw] = lastColIndex
		tgwOptionalCols[tgw] = []int{}
	}
	// each tgw has a MinCol and a maxCol. (the optional cols of the tgw are in this range).
	// we iterate over the lines, and update these values:
	for _, line := range getAllLines(ly.network) {
		tgw := line.Router()
		if _, ok := tgwMinCol[tgw]; ok {
			srcLocation := line.Src().Parent().Location()
			dstLocation := line.Dst().Parent().Location()
			tgwMinCol[tgw] = max(tgwMinCol[tgw], min(srcLocation.firstCol.index, dstLocation.firstCol.index))
			tgwMaxCol[tgw] = min(tgwMaxCol[tgw], max(srcLocation.lastCol.index, dstLocation.lastCol.index))
		}
	}
	for _, tgw := range tgws {
		// in the case there is no range, we flip MinCol and maxCol:
		if tgwMinCol[tgw] > tgwMaxCol[tgw] {
			tgwMinCol[tgw], tgwMaxCol[tgw] = tgwMaxCol[tgw], tgwMinCol[tgw]
		}
	}
	// we collect the optional cols for each tgw:
	allCols = map[int]bool{}
	for ci := firstColIndex; ci <= lastColIndex; ci++ {
		col := ly.matrix.cols[ci]
		if col.width() >= iconSpace {
			allCols[ci] = true
			for _, tgw := range tgws {
				if ci >= tgwMinCol[tgw] && ci <= tgwMaxCol[tgw] {
					tgwOptionalCols[tgw] = append(tgwOptionalCols[tgw], ci)
				}
			}
		}
	}
	return tgwOptionalCols, allCols
}

// every connection to a group square is done via a grouping point
// calcGroupingIconLocation() calc the raw and column of a group point depend of the locations of the group, and the colleague group
// the group points are located in the column outside the subnet. in the left or in the right. depend on the colleague location
func calcGroupingIconLocation(location, collLocation *Location) (r *row, c *col) {
	switch {
	case location.lastRow.index < collLocation.firstRow.index:
		r = location.lastRow
	case location.firstRow.index > collLocation.lastRow.index:
		r = location.firstRow
	case location.firstRow.index > collLocation.firstRow.index:
		r = location.firstRow
	default:
		r = collLocation.firstRow
	}

	switch {
	case location.lastCol.index < collLocation.firstCol.index:
		c = location.nextCol()
	case location.firstCol.index > collLocation.lastCol.index:
		c = location.prevCol()
	default:
		c = location.prevCol()
	}
	return r, c
}

// setGroupingIconLocations() set each group point its location and offsets.
// the offset is set according to the group visibility - we put the icon on the square border line
func (ly *layoutS) setGroupingIconLocations() {
	// groupBorder represent a right/left border of a cell of a group.
	// for each groupBorder we collect its icons
	type groupBorder struct {
		r          *row
		c          *col
		right      bool
		visibility groupSquareVisibility
	}
	iconsInBorder := map[groupBorder][]IconTreeNodeInterface{}
	for _, tn := range getAllIcons(ly.network) {
		if !tn.IsGroupingPoint() {
			continue
		}
		// choosing the right cell for the icon:
		gIcon := tn.(*GroupPointTreeNode)
		parent := gIcon.Parent().(*GroupSquareTreeNode)
		colleague := gIcon.getColleague()
		parentLocation := parent.Location()
		colleagueLocation := colleague.Location()
		if colleague.IsGroupingPoint() {
			colleagueLocation = colleague.Parent().Location()
		}
		r, c := calcGroupingIconLocation(parentLocation, colleagueLocation)
		gIcon.setLocation(newCellLocation(r, c))
		// add the icon to its border:
		groupBorder := groupBorder{
			c:          c,
			r:          r,
			visibility: parent.visibility,
			right:      c == parentLocation.nextCol(),
		}
		iconsInBorder[groupBorder] = append(iconsInBorder[groupBorder], gIcon)
		// set the x offset to the icons:
		switch parent.visibility {
		case theSubnet:
			gIcon.Location().xOffset = gIcon.Location().firstCol.width() / 2
		case square:
			gIcon.Location().xOffset = (gIcon.Location().firstCol.width()/2 + groupBorderWidth)
		case innerSquare:
			gIcon.Location().xOffset = (gIcon.Location().firstCol.width()/2 + groupBorderWidth + groupInnerBorderWidth)
		case connectedPoint:
			gIcon.connectGroupedIcons()
		}
		if c == parentLocation.nextCol() {
			// its in right to the groupSquare, so the offset is negative.
			gIcon.Location().xOffset = -gIcon.Location().xOffset
		}
	}
	// set the y offset of each icon according to:
	// 1. the number of icons in the border:
	// 2. the length of the border
	// 3. the offset of the border group
	for border, borderIcons := range iconsInBorder {
		borderLength := border.r.height()
		cellOffset := 0

		if border.visibility == square || innerSquare == border.visibility {
			groupLocation := borderIcons[0].Parent().Location()
			if border.r == groupLocation.firstRow { // its the top cell
				borderLength -= groupLocation.yOffset
				cellOffset += groupLocation.yOffset / 2
			}
			if border.r == groupLocation.lastRow { // its the bottom cell
				borderLength -= groupLocation.yEndOffset
				cellOffset -= groupLocation.yEndOffset / 2
			}
		}
		for i, gIcon := range borderIcons {
			gIcon.Location().yOffset = borderLength*(2*i-len(borderIcons)+1)/(len(borderIcons)+1)/2 + cellOffset
		}
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////
// if vsi icon shares by several subnet - we put it below one of the subnets
// else we put it inside the subnet
// gateway we put at the top
func setZoneIconsLocations(zone SquareTreeNodeInterface) {
	for _, icon := range zone.IconTreeNodes() {
		if icon.IsVSI() {
			vsiIcon := icon.(*VsiTreeNode)
			vsiSubnets := vsiIcon.GetVsiNIsSubnets()
			if len(vsiSubnets) == 1 {
				// all the NIs of the vsi are at the same subnet. in this case:
				// 1. we calculate the location of all NIs (its the minimal square contains all NIs)
				// 2. we set the icon location to be the top left cell of this square
				// 3. we give the vsi yOffset to put it belows the NIs.
				// (in case that the NIs square has more than one row, the yOffset is bigger
				nisCombinedLocation := mergeLocations(locations(vsiIcon.nis))
				icon.setLocation(newCellLocation(nisCombinedLocation.firstRow, nisCombinedLocation.firstCol))
				if nisCombinedLocation.firstRow == nisCombinedLocation.lastRow {
					vsiIcon.Location().yOffset = vsiOneRowYOffset
				} else {
					vsiIcon.Location().yOffset = vsiMultiRowYOffset
				}
			} else {
				// the NIs are on different subnets. in this case:
				// we take the first subnet, and put the vis icon below it, and also give it an xOffset
				vpcLocation := icon.(*VsiTreeNode).nis[0].Parent().Location()
				location := newCellLocation(vpcLocation.nextRow(), vpcLocation.firstCol)
				location.xOffset = subnetWidth/2 - iconSize/2
				vsiIcon.setLocation(location)
			}
		} else if icon.IsGateway() {
			col := zone.(*ZoneTreeNode).subnets[0].Location().firstCol
			row := zone.Location().firstRow
			zone.Location().firstRow.setHeight(iconSpace)
			icon.setLocation(newCellLocation(row, col))
			icon.Location().xOffset -= subnetWidth/2 - iconSize/2
		}
	}
}

func (ly *layoutS) setIconsLocations() {
	for _, cloud := range ly.network.(*NetworkTreeNode).clouds {
		for _, region := range cloud.(*CloudTreeNode).regions {
			for _, vpc := range region.(*RegionTreeNode).vpcs {
				for _, zone := range vpc.(*VpcTreeNode).zones {
					setZoneIconsLocations(zone)
				}
				ly.setIconsLocationsOnTop(vpc)
			}
			ly.setTgwLocations(region)
		}
		ly.setIconsLocationsOnTop(cloud)
	}
	ly.setPublicNetworkIconsLocations()
	ly.setGroupingIconLocations()
}

func (ly *layoutS) setGeometries() {
	for _, tn := range getAllNodes(ly.network) {
		setGeometry(tn)
	}
}
func (ly *layoutS) setRouterPoints() {
	for _, tn := range getAllLines(ly.network) {
		tn.setRouterPoints()
	}
}
