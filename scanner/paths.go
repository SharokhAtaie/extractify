package scanner

import (
	"github.com/projectdiscovery/gologger"
	"regexp"
	"strings"
)

func EndpointsMatch(body []byte, filterExtensions []string) []string {

	// Regex from https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py#L29
	regexPattern := `(?:` + "`|" + `"|'|\n|\r)(((?:[a-zA-Z]{1,10}:\/\/|\/\/)[^"'\/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:\/|\.\.\/|\.\/)[^"'><,;| *()(%%$^\/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|\/][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|cfm|pl|jsp|json|js|action|html|htm|bak|do|txt|xml|xls|xlsx|key|env|pem|git|ovpn|log|secret|secrets|access|dat|db|sql|pwd|passwd|gitignore|properties|dtd|conf|cfg|config|configs|apk|cgi|sh|py|java|rb|rs|go|yml|yaml|toml|php4|zip|tar|tar.bz2|tar.gz|rar|7z|gz|dochtml|doc|docx|csv|odt|ts|phtml|php5|pdf)(?:\?[^"|^']{0,}|)))(?:` + "`|" + `"|'|\n|\r)`

	// Compile the regular expression
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		gologger.Fatal().Msgf("Error compiling regex: %s", err)
	}

	matches := re.FindAllString(string(body), -1)

	var cleanedMatches []string
	seenLines := make(map[string]bool)

	for _, match := range matches {
		// Ensure the length of match is sufficient
		if len(match) > 2 {
			// Trim the leading "./"
			cleanedMatch := strings.TrimPrefix(match[1:len(match)-1], "./")

			if strings.HasPrefix(cleanedMatch, "//") {
				continue
			}

			// Check if the cleanedMatch has an excluded extension
			include := true
			for _, ext := range filterExtensions {
				if strings.HasSuffix(cleanedMatch, "."+ext) {
					include = false
					break
				}
			}

			// Check for duplicates
			if include && !seenLines[cleanedMatch] {
				cleanedMatches = append(cleanedMatches, cleanedMatch)
				seenLines[cleanedMatch] = true
			}
		}
	}

	return cleanedMatches
}
