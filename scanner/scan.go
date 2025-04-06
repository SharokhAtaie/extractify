// https://github.com/edoardottt/cariddi

package scanner

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// SecretsMatch matches secrets from the provided data
func SecretsMatch(url string, body []byte) []SecretMatched {
	var secrets []SecretMatched

	regexes := GetSecretRegexes()

	for _, secret := range regexes {
		if matched, err := regexp.Match(secret.Regex, body); err == nil && matched {
			re := regexp.MustCompile(secret.Regex)
			matches := re.FindAllStringSubmatch(string(body), -1)

			// Skip if no matches found
			if len(matches) == 0 {
				continue
			}

			for _, match := range matches {
				// Skip empty matches
				if len(match) == 0 || match[0] == "" {
					continue
				}

				// Avoiding false positives
				var isFalsePositive = false
				for _, falsePositive := range secret.FalsePositives {
					if strings.Contains(strings.ToLower(match[0]), falsePositive) {
						isFalsePositive = true
						break
					}
				}

				if !isFalsePositive {
					secretFound := SecretMatched{Secret: secret, URL: url, Match: match[0]}
					secrets = append(secrets, secretFound)
				}
			}
		}
	}

	secrets = RemoveDuplicateSecrets(secrets)
	return secrets
}

// SecretsMatchWithCustom matches secrets using both built-in and custom patterns
func SecretsMatchWithCustom(url string, body []byte, customSecrets []Secret) []SecretMatched {
	var secrets []SecretMatched

	// First use the built-in patterns
	standardSecrets := SecretsMatch(url, body)
	secrets = append(secrets, standardSecrets...)

	// Then use the custom patterns
	for _, secret := range customSecrets {
		if matched, err := regexp.Match(secret.Regex, body); err == nil && matched {
			re := regexp.MustCompile(secret.Regex)
			matches := re.FindAllStringSubmatch(string(body), -1)

			// Skip if no matches found
			if len(matches) == 0 {
				continue
			}

			for _, match := range matches {
				// Skip empty matches
				if len(match) == 0 || match[0] == "" {
					continue
				}

				// Avoiding false positives
				var isFalsePositive = false
				for _, falsePositive := range secret.FalsePositives {
					if strings.Contains(strings.ToLower(match[0]), falsePositive) {
						isFalsePositive = true
						break
					}
				}

				if !isFalsePositive {
					secretFound := SecretMatched{Secret: secret, URL: url, Match: match[0]}
					secrets = append(secrets, secretFound)
				}
			}
		}
	}

	secrets = RemoveDuplicateSecrets(secrets)
	return secrets
}

// LoadCustomSecrets loads custom secrets from a JSON file
func LoadCustomSecrets(filename string) ([]Secret, error) {
	var customSecrets []Secret

	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(content, &customSecrets); err != nil {
		return nil, err
	}

	gologger.Verbose().Msgf("Loaded %d custom patterns from %s", len(customSecrets), filename)
	return customSecrets, nil
}
