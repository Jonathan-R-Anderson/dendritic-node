package config

import "testing"

func TestNameConfiguration(t *testing.T) {
	for _, tc := range []struct {
		cfg   AxonConfig
		valid bool
	}{
		{AxonConfig{}, true},
		{AxonConfig{NameRPC: "rpc"}, false},
		{AxonConfig{NameSuffixes: []string{"com"}}, false},
		{AxonConfig{NameRPC: "rpc", NameContract: "contract", NameSuffixes: []string{"com"}}, true},
		{AxonConfig{NameRPC: "rpc", NameContract: "contract", NameSuffixes: []string{".com"}}, false},
		{AxonConfig{NameRPC: "rpc", NameContract: "contract", NameSuffixes: []string{"com"}, NameLegacyContract: true}, false},
		{AxonConfig{NameRPC: "rpc", NameContract: "contract", NameLegacyContract: true}, true},
		{AxonConfig{NameMissingFallback: true}, false},
	} {
		if err := tc.cfg.Validate(); (err == nil) != tc.valid {
			t.Errorf("config %+v: %v", tc.cfg, err)
		}
	}
}
