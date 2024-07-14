package vpcmodel

const doubleTab = "\t\t"

func NewRulesDetails(config *VPCConfig) (*rulesDetails, error) {
	resRulesDetails := rulesDetails{}
	for _, layer := range FilterLayers {
		thisLayerRules := make(map[string]map[int]string)
		filterLayer := config.GetFilterTrafficResourceOfKind(layer)
		thisLayerRulesDetails, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		for _, rule := range thisLayerRulesDetails {
			if _, ok := thisLayerRules[rule.FilterName]; !ok {
				thisLayerRules[rule.FilterName] = map[int]string{}
			}
			thisLayerRules[rule.FilterName][rule.RuleIndex] = rule.RuleDesc
		}
		resRulesDetails[layer] = thisLayerRules
	}
	return &resRulesDetails, nil
}

// StringDetailsOfRules gets, for a specific filter (sg/nacl), a struct with relevant rules in it,
// and prints the effect of each filter (e.g. security group sg1-ky allows connection)
// and the detailed list of relevant rules
func (rules *rulesDetails) stringDetailsOfRules(filterLayerName string, listRulesInFilter []RulesInTable) string {
	//listRulesInFilterSlice := make([]string, len(listRulesInFilter))
	//for i, rulesInFilter := range listRulesInFilter {
	//
	//}
	return ""
}

//func (nl *NaclLayer) StringDetailsOfRules(listRulesInFilter []vpcmodel.RulesInTable) string {
//	strListRulesInFilter := ""
//	for _, rulesInFilter := range listRulesInFilter {
//		nacl := nl.naclList[rulesInFilter.TableIndex]
//		header := getHeaderRulesType(vpcmodel.FilterKindName(nl.Kind())+" "+nacl.Name(), rulesInFilter.RulesOfType) +
//			nacl.analyzer.StringRules(rulesInFilter.Rules)
//		strListRulesInFilter += doubleTab + header
//	}
//	return strListRulesInFilter
//}

//func (sgl *SecurityGroupLayer) StringDetailsOfRules(listRulesInFilter []vpcmodel.RulesInTable) string {
//	listRulesInFilterSlice := make([]string, len(listRulesInFilter))
//	for i, rulesInFilter := range listRulesInFilter {
//		sg := sgl.sgList[rulesInFilter.TableIndex]
//		listRulesInFilterSlice[i] = doubleTab + getHeaderRulesType(vpcmodel.FilterKindName(sgl.Kind())+" "+sg.Name(), rulesInFilter.RulesOfType) +
//			sg.analyzer.StringRules(rulesInFilter.Rules)
//	}
//	sort.Strings(listRulesInFilterSlice)
//	return strings.Join(listRulesInFilterSlice, "")
//}

func getHeaderRulesType(filter string, rType RulesType) string {
	switch rType {
	case NoRules:
		return filter + " blocks connection since there are no relevant allow rules\n"
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

// StringRules returns a string with the details of the specified rules
//func (rules *rulesDetails) StringRules(filterLayerName string, indexes []int) string {
//	strRulesSlice := make([]string, len(rules))
//	for i, ruleIndex := range rules {
//		strRule, _, _, err := na.getNACLRule(ruleIndex)
//		if err != nil {
//			return ""
//		}
//		strRulesSlice[i] = "\t\t\t" + strRule
//	}
//	sort.Strings(strRulesSlice)
//	return strings.Join(strRulesSlice, "")
//}

// ListFilterWithAction return map from filter's name to true if it allows traffic, false otherwise
// to be used by explainability printing functions
func (rules *rulesDetails) listFilterWithAction(filterLayerName string,
	listRulesInFilter []RulesInTable) map[string]bool {
	return nil
}
