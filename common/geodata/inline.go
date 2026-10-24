package geodata

// InlineIPRules replaces every geoip reference with the CIDRs it names, read
// from this process's asset location, so whoever builds the matcher needs no
// geo files. Matching is unchanged:
//   - a reference that names no CIDR is kept: an empty list would drop the
//     condition instead of never matching;
//   - a negated reference is kept when the list also holds a negated CIDR: the
//     matcher keeps negated CIDRs and negated geoip sets as two separate
//     "not in" sets, and merging them would change the result.
func InlineIPRules(rules []*IPRule) ([]*IPRule, error) {
	negatedCIDR := false
	for _, rule := range rules {
		if custom, ok := rule.Value.(*IPRule_Custom); ok && custom.Custom.ReverseMatch {
			negatedCIDR = true
		}
	}
	out := make([]*IPRule, 0, len(rules))
	for _, rule := range rules {
		geoip, ok := rule.Value.(*IPRule_Geoip)
		if !ok || geoip.Geoip.ReverseMatch && negatedCIDR {
			out = append(out, rule)
			continue
		}
		cidrs, err := loadIP(geoip.Geoip.File, geoip.Geoip.Code)
		if err != nil {
			return nil, err
		}
		if len(cidrs) == 0 {
			out = append(out, rule)
			continue
		}
		for _, cidr := range cidrs {
			out = append(out, &IPRule{Value: &IPRule_Custom{Custom: &CIDRRule{Cidr: cidr, ReverseMatch: geoip.Geoip.ReverseMatch}}})
		}
	}
	return out, nil
}

// InlineDomainRules replaces every geosite reference with the domains it
// names (after its "@" attribute filter), read from this process's asset
// location. A reference that names no domain is kept.
func InlineDomainRules(rules []*DomainRule) ([]*DomainRule, error) {
	out := make([]*DomainRule, 0, len(rules))
	for _, rule := range rules {
		site, ok := rule.Value.(*DomainRule_Geosite)
		if !ok {
			out = append(out, rule)
			continue
		}
		var domains []*DomainRule
		err := loadSite(site.Geosite.File, site.Geosite.Code, site.Geosite.Attrs, func(t Domain_Type, value []byte) {
			domains = append(domains, &DomainRule{Value: &DomainRule_Custom{Custom: &Domain{Type: t, Value: string(value)}}})
		})
		if err != nil {
			return nil, err
		}
		if len(domains) == 0 {
			out = append(out, rule)
			continue
		}
		out = append(out, domains...)
	}
	return out, nil
}
