/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
)

// //////////////////////////////////////////////////////////////////////////////////////////////

// a genericSet is a generic implementation of a set.
// the main functionality of genericSet is asKey() - conversion to a string.
// asKey() is needed for using genericSet as a key of a map
// //////////////////////////////////////////////////////////////////////////////////////////////

type GenericSet[T comparable] map[T]bool
type SetAsKey string

func (s GenericSet[T]) AsKey() SetAsKey {
	ss := []string{}
	for i := range s {
		key := ""
		rv := reflect.ValueOf(i)
		if rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
			key = fmt.Sprintf("%x", rv.Pointer())
		} else {
			key = fmt.Sprint(i)
		}
		ss = append(ss, key)
	}
	sort.Strings(ss)
	return SetAsKey(strings.Join(ss, ","))
}

func (s GenericSet[T]) AsList() []T {
	return MapKeys(s)
}

func FromList[T comparable](l []T) GenericSet[T] {
	s := GenericSet[T]{}
	for _, e := range l {
		s[e] = true
	}
	return s
}

func (s GenericSet[T]) IsIntersect(s2 GenericSet[T]) bool {
	for i := range s {
		if (s2)[i] {
			return true
		}
	}
	return false
}

// /////////////////////////////////////////////////////////////////
// AnyMapEntry() return an arbitrary (not random) entry of a map.
// Needed for cases we do not care which entry.
// it just returns the first entry returned by range
// this func is not related to genericSet,
// todo: consider moving to another file
// todo: create AnyMapEntry() for GenericSet, and use it
// /////////////////////////////////////////////////////////
func AnyMapEntry[K comparable, V any](m map[K]V) (k K, v V) {
	for k, v = range m {
		break
	}
	return k, v
}

func MapValues[K comparable, V any](m map[K]V) []V {
	return slices.Collect(maps.Values(m))
}
func MapKeys[K comparable, V any](m map[K]V) []K {
	return slices.Collect(maps.Keys(m))
}
