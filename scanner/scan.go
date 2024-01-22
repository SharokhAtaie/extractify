// https://github.com/edoardottt/cariddi

package scanner

import (
	"regexp"
	"strings"
)

func SecretsMatch(url string, body []byte) []SecretMatched {
	var secrets []SecretMatched

	regexes := GetSecretRegexes()

	for _, secret := range regexes {
		if matched, err := regexp.Match(secret.Regex, body); err == nil && matched {
			re := regexp.MustCompile(secret.Regex)
			matches := re.FindAllStringSubmatch(string(body), -1)

			// Avoiding false positives
			var isFalsePositive = false

			for _, match := range matches {
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
