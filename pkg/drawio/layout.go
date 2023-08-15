package drawio

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// layoutS is the main struct for layouting the tree nodes
// overview to the layout algorithm:
// the input to the layout algorithm is the tree itself. the output is the geometry for each node in the drawio (x, y, height, width)
// the steps:
// 1. create a 2D matrix  - for each subnet icon, it set the location in the matrix
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
	minSize      = 10
	borderWidth  = 40
	subnetWidth  = 8 * 40
	subnetHeight = 6 * 40
	iconSize     = 60
	iconSpace    = 4 * 40

	fipXOffset = -60
	fipYOffset = 30

	vsiXOffset  = 30
	vsiYOffset  = -10
	vsiIconSize = 40

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

// ///////////////////////////////////////////////////////////////
// layoutSubnetsIcons() implements a simple north-south east-west layouting:
// 1. vpcs are next to each others
// 2. zones are next to each others
// 3. subnets a above/below each other
// 4. cell can hold at most two icons
// 5. only icons with the same sg can share a cell
func (ly *layoutS) layoutSubnetsIcons() {
	ly.setDefaultLocation(ly.network, 0, 0)
	colIndex := 0
	for _, cloud := range ly.network.(*NetworkTreeNode).ibmClouds {
		ly.setDefaultLocation(cloud, 0, colIndex)
		for _, vpc := range cloud.(*IBMCloudTreeNode).vpcs {
			ly.setDefaultLocation(vpc, 0, colIndex)
			for _, zone := range vpc.(*VpcTreeNode).zones {
				rowIndex := 0
				ly.setDefaultLocation(zone, rowIndex, colIndex)
				for _, subnet := range zone.(*ZoneTreeNode).subnets {
					var iconInCurrentCell IconTreeNodeInterface = nil
					icons := subnet.IconTreeNodes()
					ly.setDefaultLocation(subnet, rowIndex, colIndex)
					for _, icon := range icons {
						if iconInCurrentCell != nil && iconInCurrentCell.SG() != icon.SG() {
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
					rowIndex++
				}
				colIndex++
			}
			if vpc.(*VpcTreeNode).zones == nil {
				colIndex++
			}
		}
		if cloud.(*IBMCloudTreeNode).vpcs == nil {
			colIndex++
		}
	}
}

// //////////////////////////////////////////////////////////////////////////////////////////
// SG can have more than one squares. so setSGLocations() will add treeNodes of the kind PartialSGTreeNode
// PartialSGTreeNode can not have more than one row. and can have only cell that contains icons that belong to the SG
func (ly *layoutS) setSGLocations() {
	for _, cloud := range ly.network.(*NetworkTreeNode).ibmClouds {
		for _, vpc := range cloud.(*IBMCloudTreeNode).vpcs {
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

func (ly *layoutS) resolveNetworkLocations() {

	allCloudsLocation := mergeLocations(locations(getAllNodes(ly.network)))
	nl := newLocation(allCloudsLocation.prevRow(), allCloudsLocation.nextRow(), allCloudsLocation.prevCol(), allCloudsLocation.nextCol())
	if ly.network.(*NetworkTreeNode).publicNetwork != nil {
		pnl := ly.matrix.allocateCellLocation(3, 1)
		pnl.lastRow = allCloudsLocation.lastRow
		pnl.firstCol.setWidth(borderWidth)
		ly.network.(*NetworkTreeNode).publicNetwork.setLocation(pnl)
		nl.firstCol = pnl.prevCol()
	}
	nl.firstRow.setHeight(borderWidth)
	nl.lastRow.setHeight(borderWidth)
	nl.firstCol.setWidth(borderWidth)
	nl.lastCol.setWidth(borderWidth)
	ly.network.setLocation(nl)

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
	for _, cloud := range ly.network.(*NetworkTreeNode).ibmClouds {
		ly.resolveSquareLocation(cloud, cloudToSubnetDepth, true)
		for _, vpc := range cloud.(*IBMCloudTreeNode).vpcs {
			ly.resolveSquareLocation(vpc, vpcToSubnetDepth, true)
			for _, zone := range vpc.(*VpcTreeNode).zones {
				ly.resolveSquareLocation(zone, zoneToSubnetDepth, true)
				for _, subnet := range zone.(*ZoneTreeNode).subnets {
					ly.resolveSquareLocation(subnet, 0, true)
				}
			}
		}
	}
	ly.resolveNetworkLocations()
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
					vsiIcon.Location().yOffset = iconSize
				} else {
					vsiIcon.Location().yOffset = subnetHeight / 2
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
	for _, cloud := range ly.network.(*NetworkTreeNode).ibmClouds {
		for _, vpc := range cloud.(*IBMCloudTreeNode).vpcs {
			for _, zone := range vpc.(*VpcTreeNode).zones {
				ly.setZoneIconsLocations(zone)
			}
			ly.setVpcIconsLocations(vpc)
		}
	}
	ly.setPublicNetworkIconsLocations()
}

func (ly *layoutS) setGeometries() {
	for _, tn := range getAllNodes(ly.network) {
		tn.setGeometry()
	}
}
