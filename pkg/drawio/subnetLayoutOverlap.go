package drawio

// the lineExitDirection is a value from 1 -> 16, like a clock with 16 hours. 0 means NA
// 14 15 16 01 02
// 13          03
// 12          04
// 11          05
// 10 09 08 07 06
type lineExitDirection int

type subnetLayoutOverlap struct {
	xIndexes map[*col]int
	yIndexes map[*row]int
	network  TreeNodeInterface
}

func newSubnetLayoutOverlap(network TreeNodeInterface, m *layoutMatrix) *subnetLayoutOverlap {
	lyO := subnetLayoutOverlap{xIndexes: map[*col]int{}, yIndexes: map[*row]int{}, network: network}
	x, y := 0, 0
	for _, c := range m.cols {
		if c.width() >= subnetWidth {
			lyO.xIndexes[c] = x
			x++
		}
	}
	for _, r := range m.rows {
		if r.height() >= subnetHeight {
			lyO.yIndexes[r] = y
			y++
		}
	}
	return &lyO
}
func isPointInSquare(sq SquareTreeNodeInterface, x, y int) bool {
	xMin, yMin := absoluteGeometry(sq)
	xMax, yMax := xMin+sq.Width(), yMin+sq.Height()
	return x >= xMin && x <= xMax && y >= yMin && y <= yMax
}

func (lyO *subnetLayoutOverlap) addPoint(line LineTreeNodeInterface) {
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
		if max(src.Width()/2, dst.Width()/2) > max(src.Height()/2, dst.Height()/2) {
			y = midY + max(src.Height()/2, dst.Height()/2) + subnetHeight/2
			x = midX
			line.addPoint(x-minSize, y)
			line.addPoint(x+minSize, y)
		} else {
			y = midY
			x = midX + max(src.Width()/2, dst.Width()/2) + subnetWidth/2
			line.addPoint(x, y-minSize)
			line.addPoint(x, y+minSize)
		}
		return
	case abs(dX) < minSize:
		y = midY
		x = midX + max(src.Width()/2, dst.Width()/2) + subnetWidth/2
	case abs(dY) < minSize:
		y = midY + max(src.Height()/2, dst.Height()/2) + subnetHeight/2
		x = midX
	default:
		potentialXs := []int{
			midX + src.Width()/2 + subnetWidth/2,
			midX + dst.Width()/2 + subnetWidth/2,
			midX - src.Width()/2 - subnetWidth/2,
			midX - dst.Width()/2 - subnetWidth/2,
		}
		potentialYs := []int{
			midY + src.Height()/2 + subnetHeight/2,
			midY + dst.Height()/2 + subnetHeight/2,
			midY - src.Height()/2 - subnetHeight/2,
			midY - dst.Height()/2 - subnetHeight/2,
		}
		potentialPoints := []point{}
		for _, px := range potentialXs {
			py := midY + (midX-px)*dX/dY
			potentialPoints = append(potentialPoints, point{px, py})
		}
		for _, py := range potentialYs {
			px := midY + (midY-py)*dY/dX
			potentialPoints = append(potentialPoints, point{px, py})
		}
		score := 10000000
		for _, point := range potentialPoints {
			if !isPointInSquare(src, point.X, point.Y) && !isPointInSquare(dst, point.Y, point.Y) {
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

func (lyO *subnetLayoutOverlap) tnCenter(tn TreeNodeInterface) (int, int) {
	l := tn.Location()
	return lyO.xIndexes[l.firstCol] + lyO.xIndexes[l.lastCol] + 1, lyO.yIndexes[l.firstRow] + lyO.yIndexes[l.lastRow] + 1
}
func (lyO *subnetLayoutOverlap) tnSize(tn TreeNodeInterface) (int, int) {
	l := tn.Location()
	return (lyO.xIndexes[l.lastCol] - lyO.xIndexes[l.firstCol] + 1) * 2, (lyO.yIndexes[l.lastRow] - lyO.yIndexes[l.firstRow] + 1) * 2

}
func (lyO *subnetLayoutOverlap) fixOverlapping() {

	for _, tn1 := range getAllNodes(lyO.network) {
		if !tn1.IsLine() {
			continue
		}
		l1 := tn1.(LineTreeNodeInterface)
		if !l1.Src().IsSquare() || !l1.Dst().IsSquare() {
			continue
		}
		if l1.Src() == l1.Dst() {
			continue
		}
		if len(l1.Points()) > 0 {
			continue
		}
		if lyO.squaresOverlap(l1) {
			lyO.addPoint(l1)
		}
		for _, tn2 := range getAllNodes(lyO.network) {
			if !tn2.IsLine() || tn1 == tn2 {
				continue
			}
			l2 := tn2.(LineTreeNodeInterface)
			if !l2.Src().IsSquare() || !l2.Dst().IsSquare() {
				continue
			}
			if len(l1.Points()) > 0 || len(l2.Points()) > 0 {
				continue
			}
			if l1.SrcExitDirection() > 0 || l2.SrcExitDirection() > 0 {
				continue
			}
			if !lyO.linesOverlap(l1, l2) {
				continue
			}
			// fmt.Println("overlap Lines: " + tn1.Label() + " " + tn2.Label())
			ep := lyO.currentExitPoint(l1)
			ep = ep + 1
			if ep == 17 {
				ep = 1
			}
			l1.setSrcExitDirection(ep)
		}
	}
}

func (lyO *subnetLayoutOverlap) linesOverlap(l1, l2 LineTreeNodeInterface) bool {
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
	// is same graph?
	if dx1*(srcY2-srcY1) != dy1*(srcX2-srcX1) {
		return false
	}
	// share domain?
	if (minX1 >= maxX2 || minX2 >= maxX1) && (minY1 >= maxY2 || minY2 >= maxY1) {
		// fmt.Println("not same domain: " + tn1.Label() + " " + tn2.Label())
		return false
	}
	// fmt.Println("overlap Lines: " + tn1.Label() + " " + tn2.Label())
	return true
}

func (lyO *subnetLayoutOverlap) currentExitPoint(l LineTreeNodeInterface) lineExitDirection {
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
