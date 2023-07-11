package drawio

import "math"

type overlapCell struct {
	hasLine    bool
	hasOverlap bool
	icon       IconTreeNodeInterface
	pointAdded int
}

type layoutOverlap struct {
	overlapMap [5000][5000]overlapCell
}

func (lyO *layoutOverlap) cell(x, y int) *overlapCell {
	return &(lyO.overlapMap[y/minSize][x/minSize])
}

func (lyO *layoutOverlap) fixOverlapping(network TreeNodeInterface) {
	lyO.createOverlappingMap(network)
}

func getBypassPoint(icon IconTreeNodeInterface, p1 point, p2 point, try int) point {
	dx, dy := (p1.X - p2.X), (p1.Y - p2.Y)
	dis := int(math.Sqrt(float64(dx)*float64(dx) + float64(dy)*float64(dy))/float64(try))
	ix, iy := absoluteGeometry(icon)
	ix, iy = ix+iconSize/2, iy+iconSize/2
	return point{ ix + iconSize*dy/dis, iy - iconSize*dx/dis}
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
		lyO.cell(x, y).hasLine = true
		icon := lyO.cell(x, y).icon
		if icon != nil && icon != line.Src() && icon != line.Dst() && icon != line.Router() {
			lyO.cell(x, y).hasOverlap = true
			return icon
		}
	}
	return nil
}

func (lyO *layoutOverlap) createOverlappingMap(network TreeNodeInterface) {
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
	for _, tn := range getAllNodes(network) {
		if tn.IsLine() {
			line := tn.(LineTreeNodeInterface)
			newLinePoint := []point{}
			oldLinePoints := line.Points()
			absPoints := getAbsolutePoints(line)

			for pointIndex := range absPoints {
				if pointIndex == len(absPoints)-1 {
					continue
				}
				if pointIndex != 0 {
					newLinePoint = append(newLinePoint, oldLinePoints[pointIndex-1])
				}

				p1, p2 := absPoints[pointIndex], absPoints[pointIndex+1]
				icon := lyO.getOverlappedIcon(p1, p2, line)
				if icon != nil {
					try := 1
					absP := getBypassPoint(icon, p1, p2, try)
					lyO.cell(absP.X, absP.Y).pointAdded += 1
					for lyO.getOverlappedIcon(p1, absP, line) != nil{
						try++
						absP = getBypassPoint(icon, p1, p2, try)
						lyO.cell(absP.X, absP.Y).pointAdded += 1
					}
					newLinePoint = append(newLinePoint, getRelativePoint(line,absP))
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
	return point{x,y}

}
