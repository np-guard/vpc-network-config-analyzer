package common

import (
	"sort"
	"strconv"
	"strings"
)

// //////////////////////////////////////////////////////////////////////////////////////////////

// a genericSet is a generic implementation of a set.
// the main functionality of genericSet is asKey() - conversion to a string.
// asKey() is needed for using genericSet as a key of a map
// //////////////////////////////////////////////////////////////////////////////////////////////

type GenericSet[T comparable] map[T]bool
type SetAsKey string

var interfaceIndex map[interface{}]int = map[interface{}]int{}

func (s *GenericSet[T]) AsKey() SetAsKey {
	ss := []string{}
	for i := range *s {
		if _, ok := interfaceIndex[i]; !ok {
			interfaceIndex[i] = len(interfaceIndex)
		}
		ss = append(ss, strconv.Itoa(interfaceIndex[i]))
	}
	sort.Strings(ss)
	return SetAsKey(strings.Join(ss, ","))
}

func (s *GenericSet[T]) AsList() []T {
	keys := make([]T, len(*s))
	i := 0
	for k := range *s {
		keys[i] = k
		i++
	}
	return keys
}

func (s *GenericSet[T]) IsIntersect(s2 *GenericSet[T]) bool {
	for i := range *s {
		if (*s2)[i] {
			return true
		}
	}
	return false
}
