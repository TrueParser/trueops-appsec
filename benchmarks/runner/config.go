package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type object = map[string]any

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func handlerConfig(endpoint, key, mode string) object {
	return object{"handler": "trueops_appsec", "waf": mode == "waf" || mode == "combined", "bot": mode == "bot" || mode == "combined",
		"endpoint": endpoint, "api_key": key, "timeout": "5s", "max_body_bytes": 10 << 20, "max_response_bytes": 2 << 20, "max_in_flight": 256}
}

func caddyConfig(addr, origin, root string, security object) object {
	proxy := object{"handler": "reverse_proxy", "upstreams": []object{{"dial": origin}}}
	content := []object{
		{"match": []object{{"path": []string{"/static/*"}}}, "handle": []object{{"handler": "headers", "response": object{"set": object{"X-Benchmark-Origin": []string{"owned-static"}}}}, {"handler": "file_server", "root": filepath.Join(root, "public")}}, "terminal": true},
		{"handle": []object{proxy}},
	}
	chain := []object{}
	if security != nil {
		chain = append(chain, security)
	}
	chain = append(chain, object{"handler": "subroute", "routes": content})
	routes := []object{
		{"match": []object{{"path": []string{"/excluded/*"}}}, "handle": []object{proxy}, "terminal": true},
		{"handle": chain},
	}
	return object{"admin": object{"disabled": true, "config": object{"persist": false}},
		"storage": object{"module": "file_system", "root": filepath.Join(root, "storage")},
		"logging": object{"logs": object{"default": object{"level": "INFO"}}},
		"apps":    object{"http": object{"grace_period": "2s", "servers": object{"benchmark": object{"listen": []string{addr}, "read_timeout": "30s", "read_header_timeout": "5s", "idle_timeout": "30s", "automatic_https": object{"disable": true}, "routes": routes}}}}}
}
