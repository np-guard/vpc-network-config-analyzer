package drawio

import (
	"math"
)
var NOPOINT = point{-1,-1}

type overlapCell struct {
	hasBP bool
	icon       IconTreeNodeInterface
}

type layoutOverlap struct {
	overlapMap [5000][5000]overlapCell
}

func (lyO *layoutOverlap) cell(x, y int) *overlapCell {
	return &(lyO.overlapMap[y/minSize][x/minSize])
}

func (lyO *layoutOverlap) fixOverlapping(network TreeNodeInterface) {
	lyO.setIconsMap(network)
	lyO.setOverlappingLinesPoints(network)
}

var xConst = []int{1, -1, 2, -2, 3, -3}
var yConst = []int{-1, 1, -2, 2, -3, 3}

func (lyO *layoutOverlap)calcBypassPoints(icon IconTreeNodeInterface, p1 point, p2 point) []point {
	dx, dy := (p1.X - p2.X), (p1.Y - p2.Y)
	dis := int(math.Sqrt(float64(dx)*float64(dx) + float64(dy)*float64(dy)))
	ix, iy := absoluteGeometry(icon)
	ix, iy = ix+iconSize/2, iy+iconSize/2
	BPs := []point{}
	for try := range xConst {
		bp := point{int(math.Max(0, float64(ix+xConst[try]*iconSize*dy/dis))),
			int(math.Max(0, float64(iy+yConst[try]*iconSize*dx/dis)))}
		if lyO.cell(bp.X, bp.Y).icon != nil{
			continue
		}
		for lyO.cell(bp.X, bp.Y).hasBP {
			bp = point{bp.X+minSize, bp.Y+minSize}
		}

		BPs = append(BPs, bp)
	}
	return BPs
}

func (lyO *layoutOverlap) getBypassPoint(p1, p2 point, line LineTreeNodeInterface, icon IconTreeNodeInterface) point {
	BPs := lyO.calcBypassPoints(icon, p1, p2)
	for _, BP := range BPs {
		if lyO.getOverlappedIcon(p1, BP, line) == nil && lyO.getOverlappedIcon(BP, p2, line) == nil {
			return BP
		}
	}
	for _, BP := range BPs {
		if lyO.getOverlappedIcon(p1, BP, line) == nil {
			return BP
		}
	}
	return NOPOINT
}

func getAbsolutePoints(line LineTreeNodeInterface) []point {
	absPoints := []point{}
	x, y := absoluteGeometry(line.Src())
	absPoints = append(absPoints, point{x + iconSize/2, y + iconSize/2})
	for _, p := range line.Points() {
		if line.Router() != nil {
			x, y := line.Router().absoluteRouterGeometry()
			absPoints = append(absPoints, point{x + p.X, y + p.Y})

		} else {
			absPoints = append(absPoints, point{p.X, p.Y})
		}
	}
	x, y = absoluteGeometry(line.Dst())
	absPoints = append(absPoints, point{x + iconSize/2, y + iconSize/2})
	return absPoints

}

func (lyO *layoutOverlap) getOverlappedIcon(p1, p2 point, line LineTreeNodeInterface) IconTreeNodeInterface {
	x1 := p1.X
	y1 := p1.Y
	x2 := p2.X
	y2 := p2.Y
	nSteps := int(math.Abs(float64(x2-x1)) + math.Abs(float64(y2-y1))/float64(minSize))

	for s := 0; s <= nSteps; s++ {
		x := x1 + (x2-x1)*s/nSteps
		y := y1 + (y2-y1)*s/nSteps
		icon := lyO.cell(x, y).icon
		if icon != nil && icon != line.Src() && icon != line.Dst() && icon != line.Router() {
			return icon
		}
	}
	return nil
}

func (lyO *layoutOverlap) setIconsMap(network TreeNodeInterface) {
	for _, tn := range getAllNodes(network) {
		if tn.IsIcon() {
			x, y := absoluteGeometry(tn)
			for ox := x; ox < x+iconSize; ox += minSize {
				for oy := y; oy < y+iconSize; oy += minSize {
					lyO.cell(ox, oy).icon = tn.(IconTreeNodeInterface)
				}
			}
		}
	}

}

func (lyO *layoutOverlap) setOverlappingLinesPoints(network TreeNodeInterface) {
	for _, tn := range getAllNodes(network) {
		if tn.IsLine() {
			line := tn.(LineTreeNodeInterface)
			newLinePoint := []point{}
			oldLinePoints := line.Points()
			absPoints := getAbsolutePoints(line)

			for pointIndex := range absPoints[0 : len(absPoints)-1] {

				srcP := absPoints[pointIndex]
				desP := absPoints[pointIndex+1]
				for {
					icon := lyO.getOverlappedIcon(srcP, desP, line)
					if icon == nil {
						break
					}
					BP := lyO.getBypassPoint(srcP, desP, line, icon)
					if BP == NOPOINT{
						break
					}
					newLinePoint = append(newLinePoint, getRelativePoint(line, BP))
					lyO.cell(BP.X, BP.Y).hasBP = true
					srcP = BP
				}

				if pointIndex < len(oldLinePoints) {
					newLinePoint = append(newLinePoint, oldLinePoints[pointIndex])
				}
			}
			line.setPoints(newLinePoint)
		}
	}
}

func getRelativePoint(line LineTreeNodeInterface, absPoint point) point {
	px, py := absoluteGeometry(line.DrawioParent())
	if line.Router() != nil {
		px, py = line.Router().absoluteRouterGeometry()
	}
	x := absPoint.X - px
	y := absPoint.Y - py
	return point{x, y}

}
