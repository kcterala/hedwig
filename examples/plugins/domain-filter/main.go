package main

import (
	"encoding/json"
	"strings"

	"github.com/extism/go-pdk"
)

// PluginInput represents the JSON input structure received from Hedwig
type PluginInput struct {
	Hook         string                 `json:"hook"`
	MessageID    string                 `json:"message_id"`
	From         string                 `json:"from"`
	To           []string               `json:"to"`
	PluginConfig map[string]interface{} `json:"plugin_config"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// PluginConfig represents the domain filter configuration
type DomainFilterConfig struct {
	BlockedDomains []string `json:"blocked_domains"`
	AllowedDomains []string `json:"allowed_domains"`
	Mode           string   `json:"mode"` // "blocklist" or "allowlist"
}

// PluginOutput represents the JSON output structure to return to Hedwig
type PluginOutput struct {
	Action   string                 `json:"action"`   // "continue", "reject", or "defer"
	Message  string                 `json:"message"`  // Optional message
	Metadata map[string]interface{} `json:"metadata"` // Optional metadata
}

// extractDomain extracts the domain from an email address
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// parsePluginConfig parses the plugin configuration from the input
func parsePluginConfig(config map[string]interface{}) (*DomainFilterConfig, error) {
	configBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	var pluginConfig DomainFilterConfig
	if err := json.Unmarshal(configBytes, &pluginConfig); err != nil {
		return nil, err
	}

	return &pluginConfig, nil
}

// logInfo calls the host's log_info function
func logInfo(message string) {
	pdk.Log(pdk.LogInfo, message)
}

// logWarn calls the host's log_warn function
func logWarn(message string) {
	pdk.Log(pdk.LogWarn, message)
}

// logError calls the host's log_error function
func logError(message string) {
	pdk.Log(pdk.LogError, message)
}

// checkDomainFilter checks if a domain should be allowed based on the configuration
func checkDomainFilter(domain string, config *DomainFilterConfig) (bool, string) {
	domain = strings.ToLower(domain)

	switch config.Mode {
	case "blocklist":
		// In blocklist mode, reject if domain is in blocked list
		for _, blocked := range config.BlockedDomains {
			if strings.ToLower(blocked) == domain {
				return false, "Domain is blocked"
			}
		}
		return true, "Domain not in blocklist"

	case "allowlist":
		// In allowlist mode, reject if domain is NOT in allowed list
		if len(config.AllowedDomains) == 0 {
			// Empty allowlist means no domains are allowed
			return false, "No domains allowed (empty allowlist)"
		}
		for _, allowed := range config.AllowedDomains {
			if strings.ToLower(allowed) == domain {
				return true, "Domain is allowed"
			}
		}
		return false, "Domain not in allowlist"

	default:
		// Default to blocklist mode if mode is not specified
		logWarn("Unknown mode '" + config.Mode + "', defaulting to blocklist")
		for _, blocked := range config.BlockedDomains {
			if strings.ToLower(blocked) == domain {
				return false, "Domain is blocked"
			}
		}
		return true, "Domain not in blocklist"
	}
}

// handleDomainFilter processes the domain filtering logic
func handleDomainFilter(input PluginInput, email string) PluginOutput {
	// Extract domain from email
	domain := extractDomain(email)
	if domain == "" {
		logError("Invalid email address: " + email)
		return PluginOutput{
			Action:  "continue",
			Message: "Invalid email address, allowing by default",
		}
	}

	// Parse plugin configuration
	pluginConfig, err := parsePluginConfig(input.PluginConfig)
	if err != nil {
		logError("Failed to parse plugin config: " + err.Error())
		return PluginOutput{
			Action:  "continue",
			Message: "Configuration error, allowing by default",
		}
	}

	// Check domain against filter
	allowed, reason := checkDomainFilter(domain, pluginConfig)

	logInfo("Checking domain '" + domain + "': " + reason)

	if !allowed {
		return PluginOutput{
			Action:  "reject",
			Message: "Domain '" + domain + "' is not allowed: " + reason,
			Metadata: map[string]interface{}{
				"domain_checked": domain,
				"filter_mode":    pluginConfig.Mode,
			},
		}
	}

	return PluginOutput{
		Action:  "continue",
		Message: "Domain '" + domain + "' passed filter",
		Metadata: map[string]interface{}{
			"domain_checked": domain,
			"filter_mode":    pluginConfig.Mode,
		},
	}
}

//export on_mail_from
func on_mail_from() uint64 {
	// Read input from host
	inputBytes := pdk.Input()

	// Parse JSON input
	var input PluginInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		logError("Failed to parse input: " + err.Error())
		output := PluginOutput{
			Action:  "continue",
			Message: "Parse error, allowing by default",
		}
		outputBytes, _ := json.Marshal(output)
		pdk.Output(outputBytes)
		return 0
	}

	logInfo("on_mail_from hook triggered for: " + input.From)

	// Handle domain filtering for sender
	output := handleDomainFilter(input, input.From)

	// Set output
	outputBytes, err := json.Marshal(output)
	if err != nil {
		logError("Failed to marshal output: " + err.Error())
		return 1
	}

	pdk.Output(outputBytes)
	return 0
}

//export on_rcpt_to
func on_rcpt_to() uint64 {
	// Read input from host
	inputBytes := pdk.Input()

	// Parse JSON input
	var input PluginInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		logError("Failed to parse input: " + err.Error())
		output := PluginOutput{
			Action:  "continue",
			Message: "Parse error, allowing by default",
		}
		outputBytes, _ := json.Marshal(output)
		pdk.Output(outputBytes)
		return 0
	}

	// Check each recipient
	for _, recipient := range input.To {
		logInfo("on_rcpt_to hook triggered for: " + recipient)

		// Handle domain filtering for recipient
		output := handleDomainFilter(input, recipient)

		// If any recipient is rejected, reject the entire message
		if output.Action == "reject" {
			output.Message = "Recipient '" + recipient + "' rejected: " + output.Message
			outputBytes, err := json.Marshal(output)
			if err != nil {
				logError("Failed to marshal output: " + err.Error())
				return 1
			}
			pdk.Output(outputBytes)
			return 0
		}
	}

	// All recipients passed
	output := PluginOutput{
		Action:  "continue",
		Message: "All recipients passed domain filter",
		Metadata: map[string]interface{}{
			"recipients_checked": len(input.To),
		},
	}

	outputBytes, err := json.Marshal(output)
	if err != nil {
		logError("Failed to marshal output: " + err.Error())
		return 1
	}

	pdk.Output(outputBytes)
	return 0
}

func main() {}
