package vpcmodel

func NewRulesDetails(config *VPCConfig) (*RulesDetails, error) {
	resRulesDetails := RulesDetails{}
	for _, layer := range FilterLayers {
		filterLayer := config.GetFilterTrafficResourceOfKind(layer)
		thisLayerRulesDetails, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		resRulesDetails = append(resRulesDetails, thisLayerRulesDetails...)
	}
	return &resRulesDetails, nil
}

// StringDetailsOfRules gets, for a specific filter (sg/nacl), a struct with relevant rules in it,
// and prints the effect of each filter (e.g. security group sg1-ky allows connection)
// and the detailed list of relevant rules
func (rules *RulesDetails) stringDetailsOfRules(filterLayerName string, listRulesInFilter []RulesInTable) string {
	return ""
}

// ListFilterWithAction return map from filter's name to true if it allows traffic, false otherwise
// to be used by explainability printing functions
func (rules *RulesDetails) listFilterWithAction(filterLayerName string,
	listRulesInFilter []RulesInTable) map[string]bool {
	return nil
}
