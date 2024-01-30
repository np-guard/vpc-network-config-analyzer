package drawio

// subnetLayoutOverlap is for handling overlaps in subnet mode.
// it handle two kind of issues:
// 1. src and dst of a line are intersect - this is solved by adding a point to the line.
//    the point should be outside both src and dst
// 2. two lines are in opposite direction - this is solved by changing the the exit point of the line from the src

type subnetLayoutOverlap struct {
	xIndexes map[*col]int
	yIndexes map[*row]int
	network  SquareTreeNodeInterface
}

func newSubnetLayoutOverlap(network SquareTreeNodeInterface, m *layoutMatrix) *subnetLayoutOverlap {
	lyO := subnetLayoutOverlap{xIndexes: map[*col]int{}, yIndexes: map[*row]int{}, network: network}
	lyO.setIndexes(m)
	return &lyO
}

// some of the calculations are done on a matrix that take in account only the thick rows and cols
// (basically ignores the border rows/cols)
// so, as first step, we indexing all the thick rows/cols (set lyO.xIndexes and lyO.yIndexes)
// later, to find the location of a square in this matrix, we take their indexes from lyO.xIndexes and lyO.yIndexes
func (lyO *subnetLayoutOverlap) setIndexes(m *layoutMatrix) {
	xi, yi := 0, 0
	for _, c := range m.cols {
		if c.width() >= subnetWidth {
			lyO.xIndexes[c] = xi
			xi++
		}
	}
	for _, r := range m.rows {
		if r.height() >= subnetHeight {
			lyO.yIndexes[r] = yi
			yi++
		}
	}
}

// //////////////////////////////////////////////////////////////////////////////////////
// fixOverlapping() is the main func for handling overlapping.
// it iterate over the lines, find and simultaneously issues of both kinds
func (lyO *subnetLayoutOverlap) fixOverlapping() {
	for _, tn1 := range getAllNodes(lyO.network) {
		if !tn1.IsLine() {
			continue
		}
		l1 := tn1.(LineTreeNodeInterface)
		if notNeedFixing(l1) {
			continue
		}
		if lyO.squaresOverlap(l1) {
			// src and dst intersect, adding a point to the line
			lyO.addPointOutsideSquares(l1)
			continue
		}
		for _, tn2 := range getAllNodes(lyO.network) {
			if !tn2.IsLine() || tn1 == tn2 {
				continue
			}
			l2 := tn2.(LineTreeNodeInterface)
			if notNeedFixing(l2) {
				continue
			}
			if lyO.isLinesOverlap(l1, l2) {
				lyO.changeLineSrcPoint(l1)
				break
			}
		}
	}
}

// //////////////////////////////////////////////////////////
// notNeedFixing() check for cases fix is not needed
func notNeedFixing(line LineTreeNodeInterface) bool {
	if !line.Src().IsSquare() || !line.Dst().IsSquare() {
		return true
	}
	if line.Src() == line.Dst() {
		// if src == dst, the drawio fix it for us, nothing to do
		return true
	}
	if len(line.Points()) > 0 {
		// we already has points on the line
		return true
	}
	if line.SrcConnectionPoint() > 0 {
		// we already change the src point of line
		return true
	}
	return false
}

// ////////////////////////////////////////////////////////////////////////////////////
// squaresOverlap() check if the src and the dst of a line are overlap
// the are overlap if they share the same row/col.
// unless one of them is a subnet, square are also overlap if there is no gap between them
func (lyO *subnetLayoutOverlap) squaresOverlap(line LineTreeNodeInterface) bool {
	src, dst := line.Src().(SquareTreeNodeInterface), line.Dst().(SquareTreeNodeInterface)
	lSrc := src.Location()
	lDst := dst.Location()
	oneIsSubnet := src.IsSubnet() || dst.IsSubnet()
	switch {
	case lyO.xIndexes[lSrc.firstCol] > lyO.xIndexes[lDst.lastCol]+1:
		return false
	case lyO.xIndexes[lSrc.lastCol] < lyO.xIndexes[lDst.firstCol]-1:
		return false
	case lyO.yIndexes[lSrc.firstRow] > lyO.yIndexes[lDst.lastRow]+1:
		return false
	case lyO.yIndexes[lSrc.lastRow] < lyO.yIndexes[lDst.firstRow]-1:
		return false
	case lyO.xIndexes[lSrc.firstCol] > lyO.xIndexes[lDst.lastCol] && oneIsSubnet:
		return false
	case lyO.xIndexes[lSrc.lastCol] < lyO.xIndexes[lDst.firstCol] && oneIsSubnet:
		return false
	case lyO.yIndexes[lSrc.firstRow] > lyO.yIndexes[lDst.lastRow] && oneIsSubnet:
		return false
	case lyO.yIndexes[lSrc.lastRow] < lyO.yIndexes[lDst.firstRow] && oneIsSubnet:
		return false
	}
	return true
}

// ///////////////////////////////////////////////////////////////////////
// addPointOutsideSquares() adds a point to the line, to fix issue of the first type.
// we first draw an imaginary line between the src and the dst.
// we draw a second imaginary line that:
//  1. vertical to the first line
//  2. intersect the first line in the middle
//
// than we choose a point that
//  1. on the second line
//  2. outside both squares
func (lyO *subnetLayoutOverlap) addPointOutsideSquares(line LineTreeNodeInterface) {
	src, dst := line.Src().(SquareTreeNodeInterface), line.Dst().(SquareTreeNodeInterface)
	xSrc, ySrc := absoluteGeometry(src)
	xDst, yDst := absoluteGeometry(dst)
	xSrc, ySrc = xSrc+src.Width()/2, ySrc+src.Height()/2
	xDst, yDst = xDst+dst.Width()/2, yDst+dst.Height()/2
	dX, dY := xDst-xSrc, yDst-ySrc
	midX, midY := (xDst+xSrc)/2, (yDst+ySrc)/2
	x, y := 0, 0
	switch {
	case abs(dY) < minSize && abs(dX) < minSize:
		// this is the case that both squares has the same center.
		if max(src.Width()/2, dst.Width()/2) > max(src.Height()/2, dst.Height()/2) {
			// width is bigger then hight, we choose a point below the center, outside both squares:
			y = midY + max(src.Height()/2, dst.Height()/2) + subnetHeight/2
			x = midX
			// in this case we needs two points, close to each other:
			line.addPoint(x-minSize, y)
			line.addPoint(x+minSize, y)
		} else {
			// hight is bigger then width, we choose a point right to the center, outside both squares:
			y = midY
			x = midX + max(src.Width()/2, dst.Width()/2) + subnetWidth/2
			line.addPoint(x, y-minSize)
			line.addPoint(x, y+minSize)
		}
		return
	case abs(dX) < minSize:
		// centers are one bellow each other, will take a point at the right to both squares
		y = midY
		x = midX + max(src.Width()/2, dst.Width()/2) + subnetWidth/2
	case abs(dY) < minSize:
		// centers are one right each other, will take a point at the below both squares
		y = midY + max(src.Height()/2, dst.Height()/2) + subnetHeight/2
		x = midX
	default:
		// we collect a list of potential points on the second line, and choose the closest of them
		// list of potential Xs:
		potentialXs := []int{
			midX + src.Width()/2 + subnetWidth/2,
			midX + dst.Width()/2 + subnetWidth/2,
			midX - src.Width()/2 - subnetWidth/2,
			midX - dst.Width()/2 - subnetWidth/2,
		}
		// list of potential Ys:
		potentialYs := []int{
			midY + src.Height()/2 + subnetHeight/2,
			midY + dst.Height()/2 + subnetHeight/2,
			midY - src.Height()/2 - subnetHeight/2,
			midY - dst.Height()/2 - subnetHeight/2,
		}
		// foreach potential X/Y, calculate its X/Y:
		// we know that for two points on a line (y2-y1) = gradient*(x2-x1)
		// the second line is vertical to the first, so the gradient == -dX/dY
		// so (py - midY)*dY = (py - midY)*(-dX)
		potentialPoints := []point{}
		for _, px := range potentialXs {
			py := midY + (midX-px)*dX/dY
			potentialPoints = append(potentialPoints, point{px, py})
		}
		for _, py := range potentialYs {
			px := midX + (midY-py)*dY/dX
			potentialPoints = append(potentialPoints, point{px, py})
		}
		// find the closest point, which is outside of both squares:
		score := max(src.Width(), dst.Width()) + max(src.Height(), dst.Height())
		for _, point := range potentialPoints {
			lyO.network.addDebugPoint(point)
			if !isPointInSquare(src, point) && !isPointInSquare(dst, point) {
				newScore := abs(point.X-midX) + abs(point.Y-midY)
				if newScore < score {
					x, y = point.X, point.Y
					score = newScore
				}
			}
		}
	}
	line.addPoint(x, y)
}

// ////////////////////////////////////////////////////////
func isPointInSquare(sq SquareTreeNodeInterface, p point) bool {
	xMin, yMin := absoluteGeometry(sq)
	xMax, yMax := xMin+sq.Width(), yMin+sq.Height()
	return p.X >= xMin && p.X <= xMax && p.Y >= yMin && p.Y <= yMax
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// isLinesOverlap() checks if two lines overlap
// both lines are are of the form Y = gradient*X + C
// gradient is dy/dx
// two points on the same line iff dx*(y2-y1) == dy*(x2-x1)

func (lyO *subnetLayoutOverlap) isLinesOverlap(l1, l2 LineTreeNodeInterface) bool {
	srcX1, srcY1 := lyO.tnCenter(l1.Src())
	srcX2, srcY2 := lyO.tnCenter(l2.Src())
	dstX1, dstY1 := lyO.tnCenter(l1.Dst())
	dstX2, dstY2 := lyO.tnCenter(l2.Dst())
	dx1, dy1 := dstX1-srcX1, dstY1-srcY1
	dx2, dy2 := dstX2-srcX2, dstY2-srcY2
	minX1, minY1 := min(srcX1, dstX1), min(srcY1, dstY1)
	minX2, minY2 := min(srcX2, dstX2), min(srcY2, dstY2)
	maxX1, maxY1 := max(srcX1, dstX1), max(srcY1, dstY1)
	maxX2, maxY2 := max(srcX2, dstX2), max(srcY2, dstY2)
	// is same gradient?
	if dx1*dy2 != dx2*dy1 {
		return false
	}
	// same gradient, is same graph?
	if dx1*(srcY2-srcY1) != dy1*(srcX2-srcX1) {
		return false
	}
	// share domain?
	if (minX1 >= maxX2 || minX2 >= maxX1) && (minY1 >= maxY2 || minY2 >= maxY1) {
		return false
	}
	return true
}

// changeLineSrcPoint() find the current connection point of the src, and changing it to the point next to it
func (lyO *subnetLayoutOverlap) changeLineSrcPoint(l LineTreeNodeInterface) {
	currentPoint := lyO.currentSrcConnectionPoint(l)
	newSrcPoint := currentPoint%maxLineConnectionPoint + 1
	l.setSrcConnectionPoint(newSrcPoint)
}

//////////////////////////////////////////////////////////////////////////////////////////
// currentSrcConnectionPoint() calc the src connection point that will be chosen by drawio.
// if connection point is not set, drawio draw the line between the centers of the squares
// the calc is too complicated to document, but it works.

//nolint:gocyclo,gomnd // its just a big case, values of lineConnectionPoint are 1 to 16
func (lyO *subnetLayoutOverlap) currentSrcConnectionPoint(l LineTreeNodeInterface) lineConnectionPoint {
	//revive:disable // these are the numbers required by drawio
	srcX1, srcY1 := lyO.tnCenter(l.Src())
	dstX1, dstY1 := lyO.tnCenter(l.Dst())
	dx1, dy1 := dstX1-srcX1, dstY1-srcY1
	srcWidth1, srcHight1 := lyO.tnSize(l.Src())

	switch {
	case dx1 > 0 && dy1 == 0:
		return 4
	case dx1 == 0 && dy1 > 0:
		return 8
	case dx1 < 0 && dy1 == 0:
		return 12
	case dx1 == 0 && dy1 < 0:
		return 16
	case dx1 > 0 && dy1 > 0 && srcHight1*dy1 == srcWidth1*dx1:
		return 6
	case dx1 < 0 && dy1 > 0 && -srcHight1*dy1 == srcWidth1*dx1:
		return 10
	case dx1 < 0 && dy1 < 0 && srcHight1*dy1 == srcWidth1*dx1:
		return 14
	case dx1 > 0 && dy1 < 0 && -srcHight1*dy1 == srcWidth1*dx1:
		return 2
	case dx1 > 0 && dy1 > 0 && srcHight1*dy1 < srcWidth1*dx1:
		return 5
	case dx1 > 0 && dy1 > 0 && srcHight1*dy1 > srcWidth1*dx1:
		return 7
	case dx1 < 0 && dy1 > 0 && -srcHight1*dy1 < srcWidth1*dx1:
		return 9
	case dx1 < 0 && dy1 > 0 && -srcHight1*dy1 > srcWidth1*dx1:
		return 11
	case dx1 < 0 && dy1 < 0 && srcHight1*dy1 > srcWidth1*dx1:
		return 13
	case dx1 < 0 && dy1 < 0 && srcHight1*dy1 < srcWidth1*dx1:
		return 15
	case dx1 > 0 && dy1 < 0 && -srcHight1*dy1 > srcWidth1*dx1:
		return 1
	case dx1 > 0 && dy1 < 0 && -srcHight1*dy1 < srcWidth1*dx1:
		return 3
	}
	return 0
}

// ///////////////////////////////////////////////////////////////////////////
// tnCenter() and tnSize() assume that the width of every row/col is 2.
// this trick alow us to work with integer
func (lyO *subnetLayoutOverlap) tnCenter(tn TreeNodeInterface) (x, y int) {
	l := tn.Location()
	return lyO.xIndexes[l.firstCol] + lyO.xIndexes[l.lastCol] + 1,
		lyO.yIndexes[l.firstRow] + lyO.yIndexes[l.lastRow] + 1
}
func (lyO *subnetLayoutOverlap) tnSize(tn TreeNodeInterface) (x, y int) {
	l := tn.Location()
	return (lyO.xIndexes[l.lastCol] - lyO.xIndexes[l.firstCol] + 1) * 2,
		(lyO.yIndexes[l.lastRow] - lyO.yIndexes[l.firstRow] + 1) * 2
}
