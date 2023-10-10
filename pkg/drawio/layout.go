package drawio

import (
	"sort"
)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// layoutS is the main struct for layouting the tree nodes
// overview to the layout algorithm:
// the input to the layout algorithm is the tree itself. the output is the geometry for each node in the drawio (x, y, height, width)
// the steps:
// 1. create a 2D matrix  - for each subnet icon, it set the location in the matrix (see details about layouting a subnet)
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
	minSize         = 10
	borderWidth     = 40
	subnetWidth     = 8 * 40
	subnetHeight    = 6 * 40
	iconSize        = 60
	groupedIconSize = 10
	iconSpace       = 4 * 40

	groupBorderWidth      = 20
	groupTopBorderWidth   = 60
	groupedIconsDistance  = 30
	groupInnerBorderWidth = 10

	fipXOffset = -70
	fipYOffset = 40

	vsiXOffset  = 30
	vsiYOffset  = -10
	vsiIconSize = 40

	vsiOneRowYOffset   = 90
	vsiMultiRowYOffset = subnetHeight / 2

	// network -> cloud -> vpc -> zone -> subnets
	networkToSubnetDepth = 4
	cloudToSubnetDepth   = 3
	vpcToSubnetDepth     = 2
	zoneToSubnetDepth    = 1
)

type layoutS struct {
	network SquareTreeNodeInterface
	matrix  *layoutMatrix
}

func newLayout(network SquareTreeNodeInterface) *layoutS {
	return &layoutS{network: network, matrix: newLayoutMatrix()}
}

func (ly *layoutS) layout() {
	// main layout algorithm:
	// 1. create a 2D matrix  - for each subnet icon, it set the location in the matrix
	ly.layoutSubnetsIcons()
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
	newLayoutOverlap(ly.network).fixOverlapping()
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
	case i1.SG() != i2.SG():
		return false
	case !i1.IsNI() || !i2.IsNI():
		return true
	case i1.(*NITreeNode).HasFip() || i2.(*NITreeNode).HasFip():
		return false
	}
	return true
}

func sortBySize(groups []SquareTreeNodeInterface) []SquareTreeNodeInterface {
	sortedBySizeGroups := make([]SquareTreeNodeInterface, len(groups))
	copy(sortedBySizeGroups, groups)
	sort.Slice(sortedBySizeGroups, func(i, j int) bool {
		return len(sortedBySizeGroups[i].(*GroupSquareTreeNode).groupies) > len(sortedBySizeGroups[j].(*GroupSquareTreeNode).groupies)
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
//				- if the group contains all the NIs of the subnet - its visibility is theSubnet
//	         - else if all the NIs in the group not in a bigger group - its visibility is square
//	         - else if all the NIs in the group are in one bigger group - its visibility is innerSquare
//	         - else its visibility is connectedPoint
func (ly *layoutS) calcGroupsVisibility(subnet SquareTreeNodeInterface) {
	sortedBySizeGroups := sortBySize(subnet.(*SubnetTreeNode).groupSquares)
	iconSquareGroups := map[IconTreeNodeInterface]map[SquareTreeNodeInterface]bool{}
	for _, groupS := range sortedBySizeGroups {
		group := groupS.(*GroupSquareTreeNode)
		if len(group.groupies) == len(subnet.(*SubnetTreeNode).NIs()) {
			group.setVisibility(theSubnet)
			continue
		}
		groupiesFormerGroups := map[SquareTreeNodeInterface]bool{}
		for _, icon := range group.groupies {
			for g := range iconSquareGroups[icon] {
				groupiesFormerGroups[g] = true
			}
		}
		if len(groupiesFormerGroups) >= 2 {
			group.setVisibility(connectedPoint)
			continue
		}
		if len(groupiesFormerGroups) == 0 {
			group.setVisibility(square)
		} else {
			group.setVisibility(innerSquare)
		}
		for _, icon := range group.groupies {
			if _, ok := iconSquareGroups[icon]; !ok {
				iconSquareGroups[icon] = map[SquareTreeNodeInterface]bool{}
			}
			iconSquareGroups[icon][group] = true
		}
	}
}

// 2. getSubnetIconsOrder() - set the order of the icons to be displayed in the subnet
//   returns [][]IconTreeNodeInterface - the order of the icons.

func (ly *layoutS) getSubnetIconsOrder(subnet SquareTreeNodeInterface) [][]IconTreeNodeInterface {
	sortedBySizeGroups := sortBySize(subnet.(*SubnetTreeNode).groupSquares)
	iconOuterGroup := map[IconTreeNodeInterface]SquareTreeNodeInterface{}
	iconInnerGroup := map[IconTreeNodeInterface]SquareTreeNodeInterface{}
	outerToInnersGroup := map[SquareTreeNodeInterface]map[SquareTreeNodeInterface]bool{}
	// collect for each group with viability square its innerSquares groups:
	for _, groupS := range sortedBySizeGroups {
		group := groupS.(*GroupSquareTreeNode)
		if group.visibility == square {
			outerToInnersGroup[group] = map[SquareTreeNodeInterface]bool{}
		}
		for _, icon := range group.groupies {
			if group.visibility == square {
				iconOuterGroup[icon] = group
			} else if group.visibility == innerSquare {
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
			iconsOrder = append(iconsOrder, innerGroup.(*GroupSquareTreeNode).groupies)
		}
		noInnerIcons := []IconTreeNodeInterface{}
		// for each outer group - add the rest of the icons:
		for _, icon := range outerGroup.groupies {
			if _, ok := iconInnerGroup[icon]; !ok {
				noInnerIcons = append(noInnerIcons, icon)
			}
		}
		iconsOrder = append(iconsOrder, noInnerIcons)
	}
	// add the rest of the icons in the subnet
	nonGroupedIcons := []IconTreeNodeInterface{}
	for _, icon := range subnet.IconTreeNodes() {
		if _, ok := iconOuterGroup[icon]; !ok {
			if icon.IsNI() {
				nonGroupedIcons = append(nonGroupedIcons, icon)
			}
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
			iconInCurrentCell.Location().xOffset = iconSize
			icon.Location().xOffset = -iconSize
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
		for _, vpc := range cloud.(*CloudTreeNode).vpcs {
			ly.setDefaultLocation(vpc, 0, colIndex)
			for _, zone := range vpc.(*VpcTreeNode).zones {
				rowIndex := 0
				ly.setDefaultLocation(zone, rowIndex, colIndex)
				for _, subnet := range zone.(*ZoneTreeNode).subnets {
					ly.setDefaultLocation(subnet, rowIndex, colIndex)
					ly.calcGroupsVisibility(subnet)
					groups := ly.getSubnetIconsOrder(subnet)
					for _, group := range groups {
						rowIndex, colIndex = ly.layoutGroupIcons(group, rowIndex, colIndex)
					}
				}
				colIndex++
			}
			if vpc.(*VpcTreeNode).zones == nil {
				colIndex++
			}
		}
		if cloud.(*CloudTreeNode).vpcs == nil {
			colIndex++
		}
	}
}

// //////////////////////////////////////////////////////////////////////////////////////////
// SG can have more than one squares. so setSGLocations() will add treeNodes of the kind PartialSGTreeNode
// PartialSGTreeNode can not have more than one row. and can have only cell that contains icons that belong to the SG
func (ly *layoutS) setSGLocations() {
	for _, cloud := range ly.network.(*NetworkTreeNode).clouds {
		for _, vpc := range cloud.(*CloudTreeNode).vpcs {
			for _, sg := range vpc.(*VpcTreeNode).sgs {
				if len(sg.IconTreeNodes()) == 0 {
					continue
				}
				sgLocation := mergeLocations(locations(getAllNodes(sg)))
				sgIconsIndexes := map[[2]int]bool{}
				for _, icon := range sg.IconTreeNodes() {
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
							psg := newPartialSGTreeNode(sg.(*SGTreeNode))
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

func (ly *layoutS) setGroupSquareOffsets(tn SquareTreeNodeInterface) {
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

func (*layoutS) resolveSquareLocation(tn SquareTreeNodeInterface, internalBorders int, addExternalBorders bool) {
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
		ly.resolveSquareLocation(cloud, cloudToSubnetDepth, true)
		for _, vpc := range cloud.(*CloudTreeNode).vpcs {
			ly.resolveSquareLocation(vpc, vpcToSubnetDepth, true)
			for _, zone := range vpc.(*VpcTreeNode).zones {
				ly.resolveSquareLocation(zone, zoneToSubnetDepth, true)
				for _, subnet := range zone.(*ZoneTreeNode).subnets {
					ly.resolveSquareLocation(subnet, 0, true)
					for _, groupSquare := range subnet.(*SubnetTreeNode).groupSquares {
						ly.resolveSquareLocation(groupSquare, 0, false)
						ly.setGroupSquareOffsets(groupSquare)
					}
				}
			}
		}
	}
	ly.resolvePublicNetworkLocations()
	ly.resolveSquareLocation(ly.network, 1, false)
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
// setVpcIconsLocations() sets all the icons in the first vpc row.
// choose the cols with width >= iconSpace, and the cols below them
func (ly *layoutS) setVpcIconsLocations(vpc SquareTreeNodeInterface) {
	icons := vpc.IconTreeNodes()
	if len(icons) == 0 {
		return
	}

	cols := []*col{}
	firstColIndex := vpc.Location().firstCol.index
	lastColIndex := vpc.Location().lastCol.index
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
	if vpc.Location().firstRow.height() < iconSpace*iconsPerCol {
		vpc.Location().firstRow.setHeight(iconSpace * iconsPerCol)
	}
	for iconIndex, icon := range icons {
		icon.setLocation(newCellLocation(vpc.Location().firstRow, cols[iconIndex/iconsPerCol]))
		icon.Location().yOffset = iconSpace*(iconIndex%iconsPerCol) - (iconSpace*(iconsPerCol-1))/2
	}
}

// every connection to a group square is done via a grouping point
// calcGroupingIconLocation() calc the raw and column of a group point depend of the locations of the group, and the colleague group
// the group points are located in the column outside the subnet. in the left or in the right. depend on the colleague location
func (ly *layoutS) calcGroupingIconLocation(location, collLocation *Location) (r *row, c *col) {
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
	type cell struct {
		r *row
		c *col
	}
	iconsInCell := map[cell]int{}
	for _, tn := range getAllNodes(ly.network) {
		if !tn.IsIcon() || !tn.(IconTreeNodeInterface).IsGroupingPoint() {
			continue
		}
		gIcon := tn.(*GroupPointTreeNode)
		parent := gIcon.Parent().(*GroupSquareTreeNode)
		colleague := gIcon.getColleague()
		parentLocation := parent.Location()
		colleagueParentLocation := colleague.Parent().Location()
		r, c := ly.calcGroupingIconLocation(parentLocation, colleagueParentLocation)

		gIcon.setLocation(newCellLocation(r, c))
		gIcon.Location().yOffset = groupedIconsDistance * iconsInCell[cell{r, c}]
		iconsInCell[cell{r, c}]++
		switch parent.visibility {
		case theSubnet:
			gIcon.Location().xOffset = gIcon.Location().firstCol.width() / 2
		case square:
			gIcon.Location().xOffset = (gIcon.Location().firstCol.width()/2 + groupBorderWidth)
		case innerSquare:
			gIcon.Location().xOffset = (gIcon.Location().firstCol.width()/2 + groupBorderWidth + groupInnerBorderWidth)
		case connectedPoint:
			gIcon.connectGroupies()
		}
		if c == parentLocation.nextCol() {
			// its in right to the groupSquare, so the offset is negative.
			gIcon.Location().xOffset = -gIcon.Location().xOffset
		}
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////
// if vsi icon shares by several subnet - we put it below one of the subnets
// else we put it inside the subnet
// gateway we put at the top
func (ly *layoutS) setZoneIconsLocations(zone SquareTreeNodeInterface) {
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
		for _, vpc := range cloud.(*CloudTreeNode).vpcs {
			for _, zone := range vpc.(*VpcTreeNode).zones {
				ly.setZoneIconsLocations(zone)
			}
			ly.setVpcIconsLocations(vpc)
		}
	}
	ly.setPublicNetworkIconsLocations()
	ly.setGroupingIconLocations()
}

func (ly *layoutS) setGeometries() {
	for _, tn := range getAllNodes(ly.network) {
		setGeometry(tn)
	}
}
