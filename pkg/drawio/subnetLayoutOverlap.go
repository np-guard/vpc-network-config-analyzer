package drawio

import "fmt"

func tnCenter(tn TreeNodeInterface) (int, int) {
	l := tn.Location()
	return l.firstRow.index + l.lastRow.index + 1, l.firstCol.index + l.lastCol.index + 1
}
func findOverlapLines(network TreeNodeInterface) {

	for _, tn1 := range getAllNodes(network) {
		for _, tn2 := range getAllNodes(network) {
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
			srcX1, srcY1 := tnCenter(l1.Src())
			srcX2, srcY2 := tnCenter(l2.Src())
			dstX1, dstY1 := tnCenter(l1.Dst())
			dstX2, dstY2 := tnCenter(l2.Dst())
			dx1, dy1 := dstX1-srcX1, dstY1-srcY1
			dx2, dy2 := dstX2-srcX2, dstY2-srcY2
			minX1, minY1 := min(srcX1, dstX1), min(srcY1, dstY1)
			minX2, minY2 := min(srcX2, dstX2), min(srcY2, dstY2)
			maxX1, maxY1 := max(srcX1, dstX1), max(srcY1, dstY1)
			maxX2, maxY2 := max(srcX2, dstX2), max(srcY2, dstY2)
			// is same gradient?
			if dx1*dy2 != dx2*dy1 {
				continue
			}
			// is same graph?
			if dx1*(srcY2-srcY1) != dy1*(srcX2-srcX1) {
				continue
			}
			// share domain?
			if (minX1 >= maxX2 || minX2 >= maxX1) && (minY1 >= maxY2 || minY2 >= maxY1) {
				fmt.Println("not overlap Lines: " + tn1.Label() + " " + tn2.Label())
				continue
			}
			fmt.Println("overlap Lines: " + tn1.Label() + " " + tn2.Label())
			// 14 15 16 01 02
			// 13          03
			// 12          04
			// 11          05
			// 10 09 08 07 06
			switch {
			case srcX1 == dstX1 && srcY1 < dstY1:
				l1.setSrcExitAngle(9)
			case srcX1 == dstX1 && srcY1 > dstY1:
				l1.setSrcExitAngle(1)
			case srcX1 < dstX1 && srcY1 < dstY1:
				l1.setSrcExitAngle(7)
			case srcX1 < dstX1 && srcY1 == dstY1:
				l1.setSrcExitAngle(5)
			case srcX1 < dstX1 && srcY1 > dstY1:
				l1.setSrcExitAngle(3)
			case srcX1 > dstX1 && srcY1 == dstY1:
				l1.setSrcExitAngle(13)
			case srcX1 > dstX1 && srcY1 > dstY1:
				l1.setSrcExitAngle(15)
			case srcX1 > dstX1 && srcY1 < dstY1:
				l1.setSrcExitAngle(11)

			}
		}
	}
}
