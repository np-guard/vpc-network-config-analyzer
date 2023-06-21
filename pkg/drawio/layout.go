package drawio

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// layoutS is the main struct for layouting the tree nodes
// overview to the layout algorithm:
// the input to the layout algorithm is the tree itself. the output is the geometry for each node in the drawio (x, y, height, wight)
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

	// network -> vpc -> zone -> subnets
	networkToSubnetDepth = 3
)

type layoutS struct {
	network SquareTreeNodeInterface
	matrix  *layoutMatrix
}

func newLayout(network SquareTreeNodeInterface) *layoutS {
	ly := &layoutS{network: network, matrix: newLayoutMatrix()}
	return ly
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
}

// ///////////////////////////////////////////////////////////////
// layoutSubnetsIcons() implements a simple north-south east-west layouting:
// 1. vpcs are next to each others
// 2. zones are next to each others
// 3. subnets a above/below each other
// 4. cell can hold at most two icons
// 5. only icons with the same sg can share a cell

func (ly *layoutS) layoutSubnetsIcons() {
	colIndex := 0
	for _, vpc := range ly.network.(*NetworkTreeNode).vpcs {
		for _, zone := range vpc.(*VpcTreeNode).zones {
			rowIndex := 0
			for _, subnet := range zone.(*ZoneTreeNode).subnets {
				var iconInCurrentCell IconTreeNodeInterface = nil
				icons := subnet.IconTreeNodes()
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
	}
}

////////////////////////////////////////////////////////////////////////////////////////////
// SG can have more than one squares. so setSGLocations() will add treeNodes of the kind PartialSGTreeNode
// PartialSGTreeNode can not have more than one row. and can have only cell that contains icons that belong to the SG

func (ly *layoutS) setSGLocations() {
	for _, vpc := range ly.network.(*NetworkTreeNode).vpcs {
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

// ///////////////////////////////////////////////////////////
// Till this stage, we had only subnets in the matrix. now we want add vpcs/zones.
// Between two subnets, there can be one layer one case, and five in another (subnet<->zone<->vpc<->vpc<->zone<->subnet)
// First we add layers to all possible borders.
// then we mark all the layers that has are needed.
// then we remove the layers that we do not need
func (ly *layoutS) addAllBorderLayers() {
	newIndexFunction := func(index int) int { return networkToSubnetDepth + networkToSubnetDepth*2*index }
	ly.matrix.resize(newIndexFunction)
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func (*layoutS) resolveSquareLocation(tn SquareTreeNodeInterface) {
	nl := mergeLocations(locations(getAllNodes(tn)))
	if !tn.IsSubnet() {
		nl = newLocation(nl.prevRow(), nl.nextRow(), nl.prevCol(), nl.nextCol())
		nl.firstRow.setHeight(borderWidth)
		nl.lastRow.setHeight(borderWidth)
		nl.firstCol.setWidth(borderWidth)
		nl.lastCol.setWidth(borderWidth)
	}
	if !tn.IsNetwork() {
		nl.prevRow().setHeight(borderWidth)
		nl.prevCol().setWidth(borderWidth)
	}
	tn.setLocation(nl)
}

func (ly *layoutS) setSquaresLocations() {
	for _, vpc := range ly.network.(*NetworkTreeNode).vpcs {
		for _, zone := range vpc.(*VpcTreeNode).zones {
			for _, subnet := range zone.(*ZoneTreeNode).subnets {
				ly.resolveSquareLocation(subnet)
			}
			ly.resolveSquareLocation(zone)
		}
		ly.resolveSquareLocation(vpc)
	}
	ly.resolveSquareLocation(ly.network)
}

// ////////////////////////////////////////////////////////////////////////////////////////
// setNetworkIconsLocations() sets all the icons in the first col.
// choose the rows with heights >= iconSpace, and the rows next to them
func (ly *layoutS) setNetworkIconsLocations() {
	icons := ly.network.IconTreeNodes()
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
	ly.network.Location().firstCol.setWidth(iconSpace * iconsPerRow)
	for iconIndex, icon := range icons {
		icon.setLocation(newCellLocation(rows[iconIndex/iconsPerRow], ly.matrix.cols[0]))
		icon.Location().xOffset = iconSpace*(iconIndex%iconsPerRow) - (iconSpace*(iconsPerRow-1))/2
	}
}

// ////////////////////////////////////////////////////////////////////////////////////////
// setVpcIconsLocations() sets all the icons in the first vpc row.
// choose the cols with wight >= iconSpace, and the cols below them
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
	icons := zone.IconTreeNodes()
	for _, icon := range icons {
		if icon.IsVSI() {
			vsiIcon := icon.(*VsiTreeNode)
			vsiSubnets := vsiIcon.GetVsiSubnets()
			if len(vsiSubnets) == 1 {
				icon.setParent(vsiIcon.nis[0].Parent())
				nisCombinedLocation := mergeLocations(locations(vsiIcon.nis))
				icon.setLocation(newCellLocation(nisCombinedLocation.firstRow, nisCombinedLocation.firstCol))
				if nisCombinedLocation.firstRow == nisCombinedLocation.lastRow {
					vsiIcon.Location().yOffset = iconSize
				} else {
					vsiIcon.Location().yOffset = subnetHeight / 2
				}
			} else {
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

// /////////////////////////////////////////////////////////////////////////////////////////////////////////
func (ly *layoutS) setIconsLocations() {
	for _, vpc := range ly.network.(*NetworkTreeNode).vpcs {
		for _, zone := range vpc.(*VpcTreeNode).zones {
			ly.setZoneIconsLocations(zone)
		}
		ly.setVpcIconsLocations(vpc)
	}
	ly.setNetworkIconsLocations()
}

/////////////////////////////////////////////////////////////////////////////////

func (ly *layoutS) setGeometries() {
	for _, tn := range getAllNodes(ly.network) {
		tn.setGeometry()
	}
}
