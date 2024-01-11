package drawio

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
func (lyO *subnetLayoutOverlap) tnCenter(tn TreeNodeInterface) (int, int) {
	l := tn.Location()
	return lyO.xIndexes[l.firstCol] + lyO.xIndexes[l.lastCol] + 1, lyO.yIndexes[l.firstRow] + lyO.yIndexes[l.lastRow] + 1
}
func (lyO *subnetLayoutOverlap) tnSize(tn TreeNodeInterface) (int, int) {
	l := tn.Location()
	return (l.firstRow.index - l.lastRow.index + 1) * 2, (l.firstCol.index - l.lastCol.index + 1) * 2

}
func (lyO *subnetLayoutOverlap) findOverlapLines() {

	for _, tn1 := range getAllNodes(lyO.network) {
		for _, tn2 := range getAllNodes(lyO.network) {
			if !tn1.IsLine() || !tn2.IsLine() || tn1 == tn2 {
				continue
			}
			l1, l2 := tn1.(LineTreeNodeInterface), tn2.(LineTreeNodeInterface)
			if !l1.Src().IsSquare() || !l1.Dst().IsSquare() || !l2.Src().IsSquare() || !l2.Dst().IsSquare() {
				continue
			}
			if l1.SrcExitAngle() > 0 || l2.SrcExitAngle() > 0 {
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
			l1.setSrcExitAngle(ep)
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

// 14 15 16 01 02
// 13          03
// 12          04
// 11          05
// 10 09 08 07 06

func (lyO *subnetLayoutOverlap) currentExitPoint(l LineTreeNodeInterface) int {
	srcX1, srcY1 := lyO.tnCenter(l.Src())
	dstX1, dstY1 := lyO.tnCenter(l.Dst())
	dx1, dy1 := dstX1-srcX1, dstY1-srcY1
	srcHight1, srcWidth1 := lyO.tnSize(l.Src())

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
