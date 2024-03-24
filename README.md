# extractify
A tool for extract Endpoints, URLs, Parameters and Secrets from contents

# Installation
```
go install github.com/SharokhAtaie/extractify@latest
```

# Usage
```
extractify -h
```

```
Usage:
  extractify [flags]

Flags:
INPUTS:
   -u, -url string   URL for scanning
   -l, -list string  List of URLs for scanning
   -f, -file string  Local file data for scanning

EXTRACTS:
   -es, -secrets     Extract secrets (default)
   -ee, -endpoints   Extract endpoints 
   -eu, -urls        Extract urls
   -ep, -parameters  Extract parameters
   -ea, -all         Extract all

OTHERS:
   -H, -header string  Set custom header
   -v, -verbose        Verbose mode
```

You can use this as stdin:
```bash
cat urls.txt | extractify -all
echo "https://google.com/path" | extractify -endpoints
```

You can integrate this tool with others, such as subjs (https://github.com/lc/subjs):
```bash
echo "https://github.com" | subjs | extractify | tee results
```

### Thanks to [@projectdiscovery](https://github.com/projectdiscovery/) and [@edoardottt](https://github.com/edoardottt/) for best tools
