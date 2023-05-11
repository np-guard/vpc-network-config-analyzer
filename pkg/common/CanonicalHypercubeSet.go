package common

import (
	"errors"
	"sort"
	"strings"
)

type CanonicalHypercubeSet struct {
	layers     map[*CanonicalIntervalSet]*CanonicalHypercubeSet
	dimensions int
}

func NewCanonicalHypercubeSet(n int) *CanonicalHypercubeSet {
	return &CanonicalHypercubeSet{
		layers:     map[*CanonicalIntervalSet]*CanonicalHypercubeSet{},
		dimensions: n,
	}
}

func (c *CanonicalHypercubeSet) Equals(other *CanonicalHypercubeSet) bool {
	if c == other {
		return true
	}
	if c.dimensions != other.dimensions {
		return false
	}
	if len(c.layers) != len(other.layers) {
		return false
	}
	if len(c.layers) == 0 {
		return true
	}
	mapByString := map[string]*CanonicalHypercubeSet{}
	for k, v := range c.layers {
		mapByString[k.String()] = v
	}
	for k, v := range other.layers {
		if w, ok := mapByString[k.String()]; !ok || !v.Equals(w) {
			return false
		}
	}
	return true
}

func copyIntervalSet(a *CanonicalIntervalSet) *CanonicalIntervalSet {
	res := a.Copy()
	return &res
}

func (c *CanonicalHypercubeSet) Union(other *CanonicalHypercubeSet) *CanonicalHypercubeSet {
	if c.dimensions != other.dimensions {
		return nil
	}
	res := NewCanonicalHypercubeSet(c.dimensions)
	remainingsFromOther := map[*CanonicalIntervalSet]*CanonicalIntervalSet{}
	for k := range other.layers {
		kCopy := k.Copy()
		remainingsFromOther[k] = &kCopy
	}
	for k, v := range c.layers {
		remainingFromSelf := copyIntervalSet(k)
		for otherKey, otherVal := range other.layers {
			commonElem := copyIntervalSet(k)
			commonElem.Intersection(*otherKey)
			if commonElem.IsEmpty() {
				continue
			}
			remainingsFromOther[otherKey].Subtraction(*commonElem)
			remainingFromSelf.Subtraction(*commonElem)
			if c.dimensions == 1 {
				res.layers[commonElem] = NewCanonicalHypercubeSet(0)
				continue
			}
			newSubElem := v.Union(otherVal)
			res.layers[commonElem] = newSubElem
		}
		if !remainingFromSelf.IsEmpty() {
			res.layers[remainingFromSelf] = v.Copy()
		}
	}
	for k, v := range remainingsFromOther {
		if !v.IsEmpty() {
			res.layers[v] = other.layers[k].Copy()
		}
	}
	res.applyElementsUnionPerLayer()
	return res
}

func (c *CanonicalHypercubeSet) IsEmpty() bool {
	return len(c.layers) == 0
}

func (c *CanonicalHypercubeSet) Intersection(other *CanonicalHypercubeSet) *CanonicalHypercubeSet {
	if c.dimensions != other.dimensions {
		return nil
	}
	res := NewCanonicalHypercubeSet(c.dimensions)
	for k, v := range c.layers {
		for otherKey, otherVal := range other.layers {
			commonELem := copyIntervalSet(k)
			commonELem.Intersection(*otherKey)
			if commonELem.IsEmpty() {
				continue
			}
			if c.dimensions == 1 {
				res.layers[commonELem] = NewCanonicalHypercubeSet(0)
				continue
			}
			newSubElem := v.Intersection(otherVal)
			if !newSubElem.IsEmpty() {
				res.layers[commonELem] = newSubElem
			}
		}
	}
	res.applyElementsUnionPerLayer()
	return res
}

func (c *CanonicalHypercubeSet) Subtraction(other *CanonicalHypercubeSet) *CanonicalHypercubeSet {
	if c.dimensions != other.dimensions {
		return nil
	}
	res := NewCanonicalHypercubeSet(c.dimensions)
	for k, v := range c.layers {
		remainingFromSelf := copyIntervalSet(k)
		for otherKey, otherVal := range other.layers {
			commonELem := copyIntervalSet(k)
			commonELem.Intersection(*otherKey)
			if commonELem.IsEmpty() {
				continue
			}
			remainingFromSelf.Subtraction(*commonELem)
			if c.dimensions == 1 {
				continue
			}
			newSubElem := v.Subtraction(otherVal)
			if !newSubElem.IsEmpty() {
				res.layers[commonELem] = newSubElem
			}
		}
		if !remainingFromSelf.IsEmpty() {
			res.layers[remainingFromSelf] = v.Copy()
		}
	}
	res.applyElementsUnionPerLayer()
	return res
}

func (c *CanonicalHypercubeSet) getIntervalSetUnion() *CanonicalIntervalSet {
	res := NewCanonicalIntervalSet()
	for k := range c.layers {
		res.Union(*k)
	}
	return res
}

func (c *CanonicalHypercubeSet) ContainedIn(other *CanonicalHypercubeSet) (bool, error) {
	if c.dimensions != other.dimensions {
		return false, errors.New("ContainedIn mismatch between num of dimensions for input args")
	}
	if c.dimensions == 1 {
		if len(c.layers) != 1 || len(other.layers) != 1 {
			return false, errors.New("unexpected object of dimension size 1")
		}
		cInterval := c.getIntervalSetUnion()
		otherInterval := other.getIntervalSetUnion()
		return cInterval.ContainedIn(*otherInterval), nil
	}

	isSubsetCount := 0
	for k, v := range c.layers {
		currentLayer := copyIntervalSet(k)
		for otherKey, otherVal := range other.layers {
			commonKey := copyIntervalSet(currentLayer)
			commonKey.Intersection(*otherKey)
			remaining := copyIntervalSet(currentLayer)
			remaining.Subtraction(*commonKey)
			if !commonKey.IsEmpty() {
				subContainment, err := v.ContainedIn(otherVal)
				if !subContainment || err != nil {
					return subContainment, err
				}
				if !remaining.IsEmpty() {
					currentLayer = remaining
				} else {
					isSubsetCount += 1
					break
				}
			}
		}
	}
	return isSubsetCount == len(c.layers), nil
}

func (c *CanonicalHypercubeSet) Copy() *CanonicalHypercubeSet {
	res := NewCanonicalHypercubeSet(c.dimensions)
	for k, v := range c.layers {
		newKey := k.Copy()
		res.layers[&newKey] = v.Copy()
	}
	return res
}

func CreateFromCube(cube []*CanonicalIntervalSet) *CanonicalHypercubeSet {
	if len(cube) == 0 {
		return nil
	}
	if len(cube) == 1 {
		res := NewCanonicalHypercubeSet(1)
		cubeVal := cube[0].Copy()
		res.layers[&cubeVal] = NewCanonicalHypercubeSet(0)
		return res
	}
	res := NewCanonicalHypercubeSet(len(cube))
	cubeVal := cube[0].Copy()
	res.layers[&cubeVal] = CreateFromCube(cube[1:])
	return res
}

func getCubeStr(cube []*CanonicalIntervalSet) string {
	strList := []string{}
	for _, v := range cube {
		strList = append(strList, "("+v.String()+")")
	}
	return "[" + strings.Join(strList, ",") + "]"
}

func (c *CanonicalHypercubeSet) String() string {
	cubesList := c.GetCubesList()
	strList := []string{}
	for _, cube := range cubesList {
		strList = append(strList, getCubeStr(cube))
	}
	sort.Strings(strList)
	return strings.Join(strList, ",")
}

func (c *CanonicalHypercubeSet) GetCubesList() [][]*CanonicalIntervalSet {
	res := [][]*CanonicalIntervalSet{}
	if c.dimensions == 1 {
		for k := range c.layers {
			res = append(res, []*CanonicalIntervalSet{k})
		}
		return res
	}
	for k, v := range c.layers {
		subRes := v.GetCubesList()
		for _, subList := range subRes {
			cube := []*CanonicalIntervalSet{k}
			cube = append(cube, subList...)
			res = append(res, cube)
		}
	}
	return res
}

func (c *CanonicalHypercubeSet) applyElementsUnionPerLayer() {
	type pair struct {
		hc *CanonicalHypercubeSet  // hypercube set object
		is []*CanonicalIntervalSet // interval-set list
	}
	equivClasses := map[string]*pair{}
	for k, v := range c.layers {
		if _, ok := equivClasses[v.String()]; ok {
			equivClasses[v.String()].is = append(equivClasses[v.String()].is, k)
		} else {
			equivClasses[v.String()] = &pair{hc: v, is: []*CanonicalIntervalSet{k}}
		}
	}
	newLayers := map[*CanonicalIntervalSet]*CanonicalHypercubeSet{}
	for _, p := range equivClasses {
		newVal := p.hc
		newKey := p.is[0]
		for i := 1; i < len(p.is); i += 1 {
			newKey.Union(*p.is[i])
		}
		newLayers[newKey] = newVal
	}
	c.layers = newLayers
}

func CreateFromCubeShort(values ...int64) *CanonicalHypercubeSet {
	cube := []*CanonicalIntervalSet{}
	for i := 0; i < len(values); i += 2 {
		cube = append(cube, CreateFromInterval(values[i], values[i+1]))
	}
	return CreateFromCube(cube)
}
