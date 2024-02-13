package common

import (
	"errors"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/intervals"
)

// CanonicalHypercubeSet is a canonical representation for set of n-dimensional cubes, from integer intervals
type CanonicalHypercubeSet struct {
	layers     map[*intervals.CanonicalIntervalSet]*CanonicalHypercubeSet
	dimensions int
}

// NewCanonicalHypercubeSet returns a new empty CanonicalHypercubeSet with n dimensions
func NewCanonicalHypercubeSet(n int) *CanonicalHypercubeSet {
	return &CanonicalHypercubeSet{
		layers:     map[*intervals.CanonicalIntervalSet]*CanonicalHypercubeSet{},
		dimensions: n,
	}
}

// Equals return true if c equals other (same canonical form)
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

// Union returns a new CanonicalHypercubeSet object that results from union of c with other
func (c *CanonicalHypercubeSet) Union(other *CanonicalHypercubeSet) *CanonicalHypercubeSet {
	if c.dimensions != other.dimensions {
		return nil
	}
	res := NewCanonicalHypercubeSet(c.dimensions)
	remainingsFromOther := map[*intervals.CanonicalIntervalSet]*intervals.CanonicalIntervalSet{}
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

// IsEmpty returns true if c is empty
func (c *CanonicalHypercubeSet) IsEmpty() bool {
	return len(c.layers) == 0
}

// Intersection returns a new CanonicalHypercubeSet object that results from intersection of c with other
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

// Subtraction returns a new CanonicalHypercubeSet object that results from subtraction other from c
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

func (c *CanonicalHypercubeSet) getIntervalSetUnion() *intervals.CanonicalIntervalSet {
	res := intervals.NewCanonicalIntervalSet()
	for k := range c.layers {
		res.Union(*k)
	}
	return res
}

// ContainedIn returns true ic other contained in c
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

// Copy returns a new CanonicalHypercubeSet object, copied from c
func (c *CanonicalHypercubeSet) Copy() *CanonicalHypercubeSet {
	res := NewCanonicalHypercubeSet(c.dimensions)
	for k, v := range c.layers {
		newKey := k.Copy()
		res.layers[&newKey] = v.Copy()
	}
	return res
}

func getCubeStr(cube []*intervals.CanonicalIntervalSet) string {
	strList := []string{}
	for _, v := range cube {
		strList = append(strList, "("+v.String()+")")
	}
	return "[" + strings.Join(strList, ",") + "]"
}

// String returns a string representation of c
func (c *CanonicalHypercubeSet) String() string {
	cubesList := c.GetCubesList()
	strList := []string{}
	for _, cube := range cubesList {
		strList = append(strList, getCubeStr(cube))
	}
	sort.Strings(strList)
	return strings.Join(strList, "; ")
}

// GetCubesList returns the list of cubes in c, each cube as a slice of CanonicalIntervalSet
func (c *CanonicalHypercubeSet) GetCubesList() [][]*intervals.CanonicalIntervalSet {
	res := [][]*intervals.CanonicalIntervalSet{}
	if c.dimensions == 1 {
		for k := range c.layers {
			res = append(res, []*intervals.CanonicalIntervalSet{k})
		}
		return res
	}
	for k, v := range c.layers {
		subRes := v.GetCubesList()
		for _, subList := range subRes {
			cube := []*intervals.CanonicalIntervalSet{k}
			cube = append(cube, subList...)
			res = append(res, cube)
		}
	}
	return res
}

func (c *CanonicalHypercubeSet) applyElementsUnionPerLayer() {
	type pair struct {
		hc *CanonicalHypercubeSet            // hypercube set object
		is []*intervals.CanonicalIntervalSet // interval-set list
	}
	equivClasses := map[string]*pair{}
	for k, v := range c.layers {
		if _, ok := equivClasses[v.String()]; ok {
			equivClasses[v.String()].is = append(equivClasses[v.String()].is, k)
		} else {
			equivClasses[v.String()] = &pair{hc: v, is: []*intervals.CanonicalIntervalSet{k}}
		}
	}
	newLayers := map[*intervals.CanonicalIntervalSet]*CanonicalHypercubeSet{}
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

// CreateFromCube returns a new CanonicalHypercubeSet created from a single input cube
// the input cube is a slice of CanonicalIntervalSet, treated as ordered list of dimension values
func CreateFromCube(cube []*intervals.CanonicalIntervalSet) *CanonicalHypercubeSet {
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

func CreateFromCubeAsIntervals(values ...*intervals.CanonicalIntervalSet) *CanonicalHypercubeSet {
	return CreateFromCube(values)
}

// CreateFromCubeShort returns a new CanonicalHypercubeSet created from a single input cube
// the input cube is given as an ordered list of integer values, where each two values
// represent the range (start,end) for a dimension value
func CreateFromCubeShort(values ...int64) *CanonicalHypercubeSet {
	cube := []*intervals.CanonicalIntervalSet{}
	for i := 0; i < len(values); i += 2 {
		cube = append(cube, intervals.CreateFromInterval(values[i], values[i+1]))
	}
	return CreateFromCube(cube)
}

func copyIntervalSet(a *intervals.CanonicalIntervalSet) *intervals.CanonicalIntervalSet {
	res := a.Copy()
	return &res
}
