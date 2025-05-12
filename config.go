package tlsguard

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Config is the plugin configuration.
type Config struct {
	// User authentication based on certificates
	Users          map[string]string `json:"users,omitempty"`
	UsernameHeader string            `json:"usernameHeader,omitempty"`
	
	// Rules for IP whitelisting and other criteria
	Rules           []RawRule         `json:"rules,omitempty"`
	ExternalData    ExternalData      `json:"externalData,omitempty"`
	RefreshInterval string            `json:"refreshInterval,omitempty"`
	RequestHeaders  map[string]string `json:"requestHeaders,omitempty"`
}

// ExternalData defines an external data source for rules.
type ExternalData struct {
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers,omitempty"`
	DataKey       string            `json:"dataKey,omitempty"` // if the data is nested in the response, specify the key here
	SkipTLSVerify bool              `json:"skipTlsVerify,omitempty"`
}

// RawRule defines a rule in the configuration.
type RawRule struct {
	Type         string            `json:"type"`
	Headers      map[string]string `json:"headers,omitempty"`
	Ranges       []string          `json:"ranges,omitempty"`
	AddInterface bool              `json:"addInterface,omitempty"`
	Rules        []RawRule         `json:"rules,omitempty"`
}

// Define rule type constants
const (
	AllOf   string = "allOf"
	AnyOf   string = "anyOf"
	NoneOf  string = "noneOf"
	IPRange string = "ipRange"
	Header  string = "header"
)

// Rule interface for all rule types
type Rule interface {
	Init() error
	Match(req *http.Request) bool
}

// RuleConfig holds the processed rules
type RuleConfig struct {
	CreationTime time.Time
	NextUpdate   *time.Time
	Rules        []Rule `json:"rules"`
}

// NewRuleConfig creates a new rule configuration from raw config.
func NewRuleConfig(config *Config) (*RuleConfig, error) {
	ruleConfig := &RuleConfig{}
	tmplData := make(map[string]interface{})

	if config.ExternalData.URL != "" {
		data, err := GetExternalData(config.ExternalData)
		if err != nil {
			return nil, err
		}
		tmplData["data"] = data[config.ExternalData.DataKey]
	}
	fmt.Printf("external data: %v\n", tmplData)

	rules, err := mapRules(tmplData, config.Rules)
	if err != nil {
		return nil, err
	}
	ruleConfig.CreationTime = time.Now()
	ruleConfig.Rules = rules

	if config.RefreshInterval != "" {
		duration, err := time.ParseDuration(config.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("error parsing refresh interval: %w", err)
		}
		nextUpdate := ruleConfig.CreationTime.Add(duration)
		ruleConfig.NextUpdate = &nextUpdate
	} else {
		ruleConfig.NextUpdate = nil
	}

	return ruleConfig, nil
}

// Init initializes all rules.
func (c *RuleConfig) Init() error {
	for _, rule := range c.Rules {
		err := rule.Init()
		if err != nil {
			return err
		}
	}
	return nil
}

// Match checks if any rule matches the request.
func (c *RuleConfig) Match(req *http.Request) bool {
	for _, rule := range c.Rules {
		if rule.Match(req) {
			return true
		}
	}
	return false
}

// mapRules converts raw rules to processed rules.
func mapRules(tmplData map[string]interface{}, rawRules []RawRule) ([]Rule, error) {
	rules := make([]Rule, 0, len(rawRules))
	for _, rawRule := range rawRules {
		var rule Rule
		switch rawRule.Type {
		case AllOf:
			rrule := &RuleAllOf{}
			allOfRules, err := mapRules(tmplData, rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = allOfRules
			rule = rrule
		case AnyOf:
			rrule := &RuleAnyOf{}
			anyOfRules, err := mapRules(tmplData, rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = anyOfRules
			rule = rrule
		case NoneOf:
			rrule := &RuleNoneOf{}
			noneOfRules, err := mapRules(tmplData, rawRule.Rules)
			if err != nil {
				return nil, fmt.Errorf("error mapping rules: %w", err)
			}
			rrule.Rules = noneOfRules
			rule = rrule
		case IPRange:
			rrule := &RuleIPRange{}
			for _, rangeStr := range rawRule.Ranges {
				val, err := templateValue(rangeStr, tmplData)
				if err != nil {
					return nil, fmt.Errorf("error templating value: %w", err)
				}
				if strings.Contains(val, ",") {
					ranges := strings.Split(val, ",")
					for _, rangeStr := range ranges {
						rangeStr = strings.TrimSpace(rangeStr)
						if rangeStr != "" {
							rrule.Ranges = append(rrule.Ranges, rangeStr)
						}
					}
				} else {
					rangeStr = strings.TrimSpace(val)
					if rangeStr != "" {
						rrule.Ranges = append(rrule.Ranges, rangeStr)
					}
				}
			}
			rrule.AddInterface = rawRule.AddInterface
			rule = rrule
		case Header:
			rrule := &RuleHeader{}
			rrule.Headers = make(map[string]string, len(rawRule.Headers))
			for key, value := range rawRule.Headers {
				val, err := templateValue(value, tmplData)
				if err != nil {
					return nil, fmt.Errorf("error templating value: %w", err)
				}
				rrule.Headers[key] = val
			}
			rule = rrule
		default:
			return nil, fmt.Errorf("unknown rule type: %s", rawRule.Type)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// RuleAllOf implements a rule that requires all sub-rules to match.
type RuleAllOf struct {
	Rules []Rule `json:"rules"`
}

func (r *RuleAllOf) Init() error {
	for _, rule := range r.Rules {
		err := rule.Init()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RuleAllOf) Match(req *http.Request) bool {
	for _, rule := range r.Rules {
		if !rule.Match(req) {
			return false
		}
	}
	return true
}

// RuleAnyOf implements a rule that requires any of the sub-rules to match.
type RuleAnyOf struct {
	Rules []Rule `json:"rules"`
}

func (r *RuleAnyOf) Init() error {
	for _, rule := range r.Rules {
		err := rule.Init()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RuleAnyOf) Match(req *http.Request) bool {
	for _, rule := range r.Rules {
		if rule.Match(req) {
			return true
		}
	}
	return false
}

// RuleNoneOf implements a rule that requires none of the sub-rules to match.
type RuleNoneOf struct {
	Rules []Rule `json:"rules"`
}

func (r *RuleNoneOf) Init() error {
	for _, rule := range r.Rules {
		err := rule.Init()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RuleNoneOf) Match(req *http.Request) bool {
	for _, rule := range r.Rules {
		if rule.Match(req) {
			return false
		}
	}
	return true
}