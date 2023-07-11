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

func (lyO *layoutOverlap) fixOverlapping(network TreeNodeInterface) {
	lyO.createOverlappingMap(network)
}

func getBypassPoint2(icons []IconTreeNodeInterface, p1 point, p2 point) (int, int) {
	ix, iy := absoluteGeometry(icons[0])
	x, y := (p1.X+p2.X+ix)/3+iconSize*2, (p1.Y+p2.Y+iy)/3+iconSize*2
	return x, y
}

func getBypassPoint(icons []IconTreeNodeInterface, p1 point, p2 point) (int, int) {
	dx, dy := (p1.X - p2.X), (p1.Y - p2.Y)
	dis := int(math.Sqrt(float64(dx)*float64(dx) + float64(dy)*float64(dy)))
	ix, iy := absoluteGeometry(icons[0])
	ix, iy = ix+iconSize/2, iy+iconSize/2
	return ix + iconSize*dy/dis, iy - iconSize*dx/dis
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
func (lyO *layoutOverlap) createOverlappingMap(network TreeNodeInterface) {
	for _, tn := range getAllNodes(network) {
		if tn.IsIcon() {
			x, y := absoluteGeometry(tn)
			for ox := x; ox < x+iconSize; ox += minSize {
				for oy := y; oy < y+iconSize; oy += minSize {
					lyO.overlapMap[oy/minSize][ox/minSize].icon = tn.(IconTreeNodeInterface)
				}
			}
		}
	}
	for _, tn := range getAllNodes(network) {
		if tn.IsLine() {
			line := tn.(LineTreeNodeInterface)
			doNotBypass := map[IconTreeNodeInterface]bool{}
			doNotBypass[line.Src()] = true
			doNotBypass[line.Dst()] = true
			if line.Router() != nil {
				doNotBypass[line.Router()] = true
			}
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
				x1 := absPoints[pointIndex].X
				y1 := absPoints[pointIndex].Y
				x2 := absPoints[pointIndex+1].X
				y2 := absPoints[pointIndex+1].Y
				nSteps := int(math.Abs(float64(x2-x1)) + math.Abs(float64(y2-y1))/float64(minSize))

				for s := 0; s <= nSteps; s++ {
					x := x1 + (x2-x1)*s/nSteps
					y := y1 + (y2-y1)*s/nSteps
					lyO.overlapMap[y/minSize][x/minSize].hasLine = true
					icon := lyO.overlapMap[y/minSize][x/minSize].icon
					if icon != nil && !doNotBypass[icon] {
						lyO.overlapMap[y/minSize][x/minSize].hasOverlap = true
						doNotBypass[icon] = true
						p1, p2 := absPoints[pointIndex], absPoints[pointIndex+1]
						x, y := getBypassPoint([]IconTreeNodeInterface{icon}, p1, p2)
						lyO.overlapMap[y/minSize][x/minSize].pointAdded += 1
						px, py := absoluteGeometry(line.DrawioParent())
						if line.Router() != nil {
							px, py = line.Router().absoluteRouterGeometry()
						}
						x -= px
						y -= py

						newLinePoint = append(newLinePoint, point{x, y})
					}
				}
			}
			line.setPoints(newLinePoint)
		}
	}
}
