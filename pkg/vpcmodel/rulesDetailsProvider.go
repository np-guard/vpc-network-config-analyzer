/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"sort"
	"strings"
)

type filterRulesDetails struct {
	tableName string
	rulesDesc map[int]string
}

// map from LayerName to map from FilterIndex to  a struct containing filter name and a map from rules indexes
// to rule description
type rulesDetails map[string]map[int]filterRulesDetails

func newRulesDetails(config *VPCConfig) (*rulesDetails, error) {
	resRulesDetails := rulesDetails{}
	for _, layer := range FilterLayers {
		thisLayerRules := make(map[int]filterRulesDetails)
		filterLayer := config.GetFilterTrafficResourceOfKind(layer)
		if filterLayer == nil {
			// todo - remove this if when we have nacl support for aws
			continue
		}
		thisLayerRulesDetails, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		for _, rule := range thisLayerRulesDetails {
			if _, ok := thisLayerRules[rule.Filter.FilterIndex]; !ok {
				thisLayerRules[rule.Filter.FilterIndex] = filterRulesDetails{
					tableName: rule.Filter.FilterName,
					rulesDesc: map[int]string{},
				}
			}
			thisLayerRules[rule.Filter.FilterIndex].rulesDesc[rule.RuleIndex] = rule.RuleDesc
		}
		resRulesDetails[layer] = thisLayerRules
	}
	return &resRulesDetails, nil
}

// stringDetailsOfLayer gets, for a specific filter (sg/nacl), a struct with relevant rules in it,
// and prints the effect of each filter (e.g. security group sg1-ky allows connection)
// and the detailed list of relevant rules
func (rules *rulesDetails) stringDetailsOfLayer(filterLayer string, listRulesInFilter []RulesInTable) string {
	listRulesInFilterSlice := make([]string, len(listRulesInFilter))
	filterLayerName := FilterKindName(filterLayer)
	rulesOfLayer := (*rules)[filterLayer]
	for i, rulesInFilter := range listRulesInFilter {
		filterName := rulesOfLayer[rulesInFilter.TableIndex].tableName
		header := getHeaderRulesType(filterLayerName+" "+filterName, rulesInFilter.RulesOfType)
		details := rules.stringRulesDetails(filterLayer, rulesInFilter.TableIndex, rulesInFilter.Rules)
		listRulesInFilterSlice[i] += doubleTab + header + details
	}
	sort.Strings(listRulesInFilterSlice)
	return strings.Join(listRulesInFilterSlice, "")
}

// stringRulesDetails returns a string with the details of the specified rules
func (rules *rulesDetails) stringRulesDetails(filterLayer string, filterIndex int, rulesIndexes []int) string {
	strRulesSlice := make([]string, len(rulesIndexes))
	rulesDetails := (*rules)[filterLayer][filterIndex].rulesDesc
	for i, ruleIndex := range rulesIndexes {
		strRulesSlice[i] = "\t\t\t" + rulesDetails[ruleIndex]
	}
	sort.Strings(strRulesSlice)
	return strings.Join(strRulesSlice, "")
}

func getHeaderRulesType(filter string, rType RulesType) string {
	switch rType {
	case NoRules:
		return filter + " has no relevant allow rules\n"
	case OnlyDeny:
		return filter + " blocks connection with the following deny rules:\n"
	case BothAllowDeny:
		return filter + " allows connection with the following allow and deny rules\n"
	case OnlyAllow:
		return filter + " allows connection with the following allow rules\n"
	default:
		return ""
	}
}

// listFilterWithAction return, given a layer, map from each of the filter's names in the layer whose index is in
// listRulesInFilter to true if it allows traffic, false otherwise.
// To be used by explainability printing functions
func (rules *rulesDetails) listFilterWithAction(filterLayer string,
	listRulesInFilter []RulesInTable) map[string]bool {
	tablesToAction := map[string]bool{}
	rulesOfLayer := (*rules)[filterLayer]
	for _, rulesInFilter := range listRulesInFilter {
		tableName := rulesOfLayer[rulesInFilter.TableIndex].tableName
		tablesToAction[tableName] = getFilterAction(rulesInFilter.RulesOfType)
	}
	return tablesToAction
}

// returns true of the filter allows traffic, false if it blocks traffic
func getFilterAction(rType RulesType) bool {
	switch rType {
	case BothAllowDeny, OnlyAllow:
		return true
	default:
		return false
	}
}
