package scanner

type Secret struct {
	Name           string
	Description    string
	Regex          string
	FalsePositives []string
	Poc            string
}

type SecretMatched struct {
	Secret Secret
	URL    string
	Match  string
}

// GetSecretRegexes returns a slice of all
func GetSecretRegexes() []Secret {

	var regexes = []Secret{
		{
			"AWS API Key",
			"AWS API Key",
			`\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b`,
			[]string{},
			"?",
		},
		{
			"AWS Secret Access Key",
			"AWS Secret Access Key",
			`(?i)\baws_?(?:secret)?_?(?:access)?_?(?:key)?["'']?\s{0,30}(?::|=>|=)\s{0,30}["'']?([a-z0-9/+=]{40})\b`,
			[]string{},
			"?",
		},
		{
			"Amazon MWS Auth Token",
			"Amazon MWS Auth Token",
			`(?i)(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`,
			[]string{},
			"?",
		},
		{
			"AWS Session Token",
			"AWS Session Token",
			`(?i)(?:aws.?session|aws.?session.?token|aws.?token)["'` + "`" + `]?[\s]{0,30}(?::|=>|=)[\s]{0,30}["'` + "`" + `]?([a-z0-9_\/+=.-]{16,1000})`,
			[]string{},
			"?",
		},
		{
			"Facebook Secret Key",
			"Facebook Secret Key",
			`(?i:\b(?:facebook|fb).?(?:api|app|application|client|consumer|customer|secret|key).?(?:key|oauth|sec|secret)?.{0,2}\s{0,20}.{0,2}\s{0,20}.{0,2}\b([a-z0-9]{32})\b)`,
			[]string{"facebook.com", "facebook.svg"},
			"?",
		},
		{
			"Github Personal Access Token",
			"Github Personal Access Token",
			`\b(ghp_[a-zA-Z0-9]{36})\b`,
			[]string{},
			"?",
		},
		{
			"Github Personal Access Token",
			"Github Personal Access Token",
			`\b(github_pat_[0-9a-zA-Z_]{82})\b`,
			[]string{},
			"?",
		},
		{
			"Github OAuth Access Token",
			"Github OAuth Access Token",
			`\b(gho_[a-zA-Z0-9]{36})\b`,
			[]string{},
			"?",
		},
		{
			"Github App Token",
			"Github App Token",
			`\b((?:ghu|ghs)_[a-zA-Z0-9]{36})\b`,
			[]string{},
			"?",
		},
		{
			"Github Refresh Token",
			"Github Refresh Token",
			`\b(ghr_[a-zA-Z0-9]{76})\b`,
			[]string{},
			"?",
		},
		{
			"Slack",
			"Slack",
			`xox[baprs]-[0-9a-zA-Z]{12,}-[0-9a-zA-Z]{12,}(?:-[0-9a-zA-Z]{12,})*`,
			[]string{},
			"?",
		},
		{
			"Heroku API Key",
			"Heroku API Key",
			`(?i)heroku.{0,20}key.{0,20}\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			[]string{},
			"?",
		},
		{
			"SendGrid API Key",
			"SendGrid API Key",
			`\b(SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})\b`,
			[]string{},
			"?",
		},
		{
			"Slack Webhook",
			"Slack Webhook",
			`(?i)(https://hooks.slack.com/services/T[a-z0-9_]{8}/B[a-z0-9_]{8,12}/[a-z0-9_]{24})`,
			[]string{},
			"?",
		},
		{
			"Stripe API key",
			"Stripe API key",
			`(?i)\b((?:sk|rk)_live_[a-z0-9]{24})\b`,
			[]string{},
			"?",
		},
		{
			"Stripe API Test Key",
			"Stripe API Test Key",
			`(?i)\b((?:sk|rk)_test_[a-z0-9]{24})\b`,
			[]string{},
			"?",
		},
		{
			"Dynatrace token",
			"Dynatrace token",
			`\b(dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64})\b`,
			[]string{},
			"?",
		},
		{
			"Shopify App Secret",
			"Shopify App Secret",
			`\b(shpss_[a-fA-F0-9]{32})\b`,
			[]string{},
			"?",
		},
		{
			"Shopify access token",
			"Shopify access token",
			`\b(shpat_[a-fA-F0-9]{32})\b`,
			[]string{},
			"?",
		},
		{
			"Shopify custom app access token",
			"Shopify custom app access token",
			`\b(shpca_[a-fA-F0-9]{32})\b`,
			[]string{},
			"?",
		},
		{
			"Shopify private app access token",
			"Shopify private app access token",
			`\b(shppa_[a-fA-F0-9]{32})\b`,
			[]string{},
			"?",
		},
		{
			"Discord Webhook URL",
			"Discord Webhook URL",
			`(?i)(https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+)`,
			[]string{},
			"?",
		},
		{
			"Google Calendar URI",
			"Google Calendar URI",
			`(?i)(https\:\/\/(.*)calendar\.google\.com\/calendar\/[0-9a-z\/]+\/embed\?src=[A-Za-z0-9%@&;=\-_\.\/]+)`,
			[]string{},
			"?",
		},
		{
			"Google OAuth Access Key",
			"Google OAuth Access Key",
			`\b(ya29\.[0-9A-Za-z_-]{20,100})(?:[^0-9A-Za-z_-]|$)`,
			[]string{},
			"?",
		},
		{
			"Mapbox Secret Access Token",
			"Mapbox Secret Access Token",
			`(?i)(?s)mapbox.{0,30}(sk\.[a-z0-9\-+/=]{32,128}\.[a-z0-9\-+/=]{20,30})(?:[^a-z0-9\-+/=]|$)`,
			[]string{},
			"?",
		},
		{
			"Mapbox Temporary Access Token",
			"Mapbox Temporary Access Token",
			`(?i)(?s)mapbox.{0,30}(tk\.[a-z0-9\-+/=]{32,128}\.[a-z0-9\-+/=]{20,30})(?:[^a-z0-9\-+/=]|$)`,
			[]string{},
			"?",
		},
		{
			"Microsoft Teams Webhook",
			"Microsoft Teams Webhook",
			`(?i)(https://outlook\.office\.com/webhook/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`,
			[]string{},
			"?",
		},
		{
			"Firebase Secret",
			"Firebase Secret",
			`\bAAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}\b`,
			[]string{},
			"?",
		},
		{
			"GitLab Personal Access Token",
			"GitLab Personal Access Token",
			`\b(glpat-[0-9a-zA-Z_-]{20})(?:\b|$)`,
			[]string{},
			"?",
		},
		{
			"GitLab Runner Registration Token",
			"GitLab Runner Registration Token",
			`\b(GR1348941[0-9a-zA-Z_-]{20})(?:\b|$)`,
			[]string{},
			"?",
		},
		{
			"GitLab Pipeline Trigger Token",
			"GitLab Pipeline Trigger Token",
			`\b(glptt-[0-9a-f]{40})\b`,
			[]string{},
			"?",
		},
		{
			"Linear API Key",
			"Linear API Key",
			`\b(lin_api_[a-zA-Z0-9]{40})\b`,
			[]string{},
			"?",
		},
		{
			"Algolia API Key",
			"Algolia API Key",
			`(?i)(algolia|application)_?key['"\s:=]+[a-zA-Z0-9]{10,}`,
			[]string{},
			"?",
		},
		{
			"Netlify Token V2",
			"Netlify Token V2",
			`\b(nfp_[a-zA-Z0-9_]{36})\b`,
			[]string{},
			"?",
		},
		{
			"CircleCI Token",
			"CircleCI Token",
			`(?i)(circle-token=[a-z0-9]{40})\b`,
			[]string{},
			"?",
		},
		{
			"GitLab Runner Token",
			"GitLab Runner Token",
			`\b(glrt-[a-zA-Z0-9_-]{20})\b`,
			[]string{},
			"?",
		},
		{
			"Snyk Token",
			"Snyk Token",
			`(?i)(snyk_token\s*=\s*[a-f0-9\-]{36})\b`,
			[]string{},
			"?",
		},
		{
			"Discord Bot Token",
			"Discord Bot Token",
			`[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`,
			[]string{},
			"?",
		},
		{
			"Riot Games API Key",
			"Riot Games API Key",
			`\b(RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`,
			[]string{},
			"?",
		},
		{
			"Generic Keys",
			"Generic Keys",
			`(?i)(?:(?:access_key|access_token|admin_pass|admin_user|algolia_admin_key|x-algolia-api-key|algolia_api_key|alias_pass|alicloud_access_key|ansible_vault_password|aos_key|api_key_secret|api_key_sid|api_secret|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_bucket|aws_key|aws_secret|aws_token|AWSSecretKey|b2_app_key|bashrc|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login|connectionstring|consumer_key|consumer_secret|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey|discovery_iam_apikey|appPassword|slackToken|slack_signing_secret|watson_assistant_api_key|pythonPassword)[a-z0-9_.\-,]{0,25})[:<>=|]{1,2}.{0,5}['"]([0-9a-zA-Z\-_=]{8,64})['"]`,
			[]string{},
			"?",
		},
		{
			"JWT Token",
			"Check For JWT Token",
			`eyJ[0-9A-Za-z-_]+\.[0-9A-Za-z-_]+\.[0-9A-Za-z-_]{43,}`,
			[]string{},
			"?",
		},
		{
			"Secrets From js miner",
			"Check Keys in keyhacks",
			`(?i)['"` + "`]?(\\w*)" + // Starts with a quote then a word / white spaces
				`(\s*)` +
				`(secret|passwd|authorization|bearer|irc_pass|SLACK_BOT_TOKEN|id_dsa|` +
				`secret[_-]?(key|token|secret)|` +
				`api[_-]?(key|token|secret)|` +
				`access[_-]?(key|token|secret)|` +
				`auth[_-]?(key|token|secret)|` +
				`session[_-]?(key|token|secret)|` +
				`consumer[_-]?(key|token|secret)|` +
				`public[_-]?(key|token|secret)|` +
				`ssh[_-]?key|` +
				`encrypt[_-]?(secret|key)|` +
				`decrypt[_-]?(secret|key)|` +
				`github[_-]?(key|token|secret)|` +
				`slack[_-]?token)` +
				`(\w*)` + // in case there are any characters / white spaces
				`(\s*)` +
				`['"` + "`]?" + // closing quote for variable name
				`(\s*)` + // white spaces
				`[:=]+[:=>]?` + // assignments operation
				`(\s*)` +
				`['"` + "`]" + // opening quote for secret
				`(\s*)` +
				`([\w\-/~!@#$%^&*+]+)` + // Assuming secrets will be alphanumeric with some special characters
				`(\s*)` +
				`['"` + "`]",
			[]string{},
			"?"},
		{
			"NuGet API Key",
			"NuGet API Key",
			`\b(oy2[a-z0-9]{43})\b`,
			[]string{},
			"?",
		},
		{
			"Okta API Token",
			"Okta API Token",
			`(?i)(?s)(?:okta|ssws).{0,40}\b(00[a-z0-9_-]{39}[a-z0-9_])\b`,
			[]string{},
			"?",
		},
		{
			"OpenAI API Key",
			"OpenAI API Key",
			`\b(sk-[a-zA-Z0-9]{48})\b`,
			[]string{},
			"?",
		},
		{
			"Postman API Key",
			"Postman API Key",
			`\b(PMAK-[a-zA-Z0-9]{24}-[a-zA-Z0-9]{34})\b`,
			[]string{},
			"?",
		},
		{
			"PyPI Upload Token",
			"PyPI Upload Token",
			`\b(pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,})(?:[^a-zA-Z0-9_-]|$)`,
			[]string{},
			"?",
		},
		{
			"RubyGems API Key",
			"RubyGems API Key",
			`\b(rubygems_[a-f0-9]{48})\b`,
			[]string{},
			"?",
		},
		{
			"Salesforce Access Token",
			"Salesforce Access Token",
			`\b(00[a-zA-Z0-9]{13}![a-zA-Z0-9._]{96})(?:\b|$|[^a-zA-Z0-9._])`,
			[]string{},
			"?",
		},
		{
			"Segment Public API Token",
			"Segment Public API Token",
			`\b(sgp_[a-zA-Z0-9]{64})\b`,
			[]string{},
			"?",
		},
		{
			"StackHawk API Key",
			"StackHawk API Key",
			`\b(hawk\.[0-9A-Za-z_-]{20}\.[0-9A-Za-z_-]{20})\b`,
			[]string{},
			"?",
		},
		{
			"Telegram Bot Token",
			"Telegram Bot Token",
			`\b(\d+:AA[a-zA-Z0-9_-]{32,33})(?:[^a-zA-Z0-9_-]|$)`,
			[]string{},
			"?",
		},
		{
			"Twitter Secret Key",
			"Twitter Secret Key",
			`twitter.?(?:api|app|application|client|consumer|customer|secret|key)?.?(?:key|oauth|sec|secret)?.{0,2}\s{0,20}.{0,2}\s{0,20}.{0,2}\b([a-z0-9]{35,44})\b`,
			[]string{},
			"?",
		},
		{
			"HuggingFace User Access Token",
			"HuggingFace User Access Token",
			`\b(hf_[a-zA-Z]{34})\b`,
			[]string{},
			"?",
		},
		{
			"Jenkins Crumb Token",
			"Jenkins Crumb Token",
			`Jenkins-Crumb:\s*[a-z0-9]{30,}`,
			[]string{},
			"?",
		},
		{
			"Jenkins Token or Crumb",
			"Jenkins Token or Crumb",
			`(?i)jenkins.{0,10}(?:crumb)?.{0,10}\b([0-9a-f]{32,36})\b`,
			[]string{},
			"?",
		},
		{
			"MailChimp API Key",
			"MailChimp API Key",
			`(?:mailchimp|mc).{0,20}\b([a-f0-9]{32}-us[0-9]{1,3})\b`,
			[]string{},
			"?",
		},
		{
			"Mailgun API Key",
			"Mailgun API Key",
			`(?i)(?:mailgun|mg).{0,20}key-([a-z0-9]{32})\b`,
			[]string{},
			"?",
		},
		{
			"New Relic License Key",
			"New Relic License Key",
			`\b([a-z0-9]{6}[a-f0-9]{30}nral)\b`,
			[]string{},
			"?",
		},
		{
			"New Relic API Service Key",
			"New Relic API Service Key",
			`\b(nrak-[a-z0-9]{27})\b`,
			[]string{},
			"?",
		},
		{
			"New Relic Admin API Key",
			"New Relic Admin API Key",
			`\b(nraa-[a-f0-9]{27})\b`,
			[]string{},
			"?",
		},
		{
			"New Relic Insights Insert Key",
			"New Relic Insights Insert Key",
			`\b(nrii-[a-z0-9_-]{32})(?:[^a-z0-9_-]|$)`,
			[]string{},
			"?",
		},
		{
			"New Relic Insights Query Key",
			"New Relic Insights Query Key",
			`\b(nriq-[a-z0-9_-]{32})(?:[^a-z0-9_-]|$)`,
			[]string{},
			"?",
		},
		{
			"New Relic REST API Key",
			"New Relic REST API Key",
			`\b(nrra-[a-f0-9]{42})\b`,
			[]string{},
			"?",
		},
		{
			"New Relic Pixie API Key",
			"New Relic Pixie API Key",
			`\b(px-api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
			[]string{},
			"?",
		},
		{
			"New Relic Pixie Deploy Key",
			"New Relic Pixie Deploy Key",
			`\b(px-dep-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
			[]string{},
			"?",
		},
		{
			"NPM Access Token (fine-grained)",
			"NPM Access Token (fine-grained)",
			`\b(npm_[A-Za-z0-9]{36})\b`,
			[]string{},
			"?",
		},
		{
			"Artifactory API Key",
			"Artifactory API Key",
			`(?i)artifactory.{0,50}\b([a-z0-9]{73})\b`,
			[]string{},
			"?",
		},
		{
			"Azure App Configuration Connection String",
			"Azure App Configuration Connection String",
			`(https://[a-zA-Z0-9-]+\.azconfig\.io);Id=(.{4}-.{2}-.{2}:[a-zA-Z0-9+/]{18,22});Secret=([a-zA-Z0-9+/]{36,50}=)`,
			[]string{},
			"?",
		},
		{
			"crates.io API Key",
			"crates.io API Key",
			`\b(cio[a-zA-Z0-9]{32})\b`,
			[]string{},
			"?",
		},
		{
			"Dependency-Track API Key",
			"Dependency-Track API Key",
			`\b(odt_[A-Za-z0-9]{32,255})\b`,
			[]string{},
			"?",
		},
		{
			"DigitalOcean Application Access Token",
			"DigitalOcean Application Access Token",
			`\b(doo_v1_[a-f0-9]{64})\b`,
			[]string{},
			"?",
		},
		{
			"DigitalOcean Personal Access Token",
			"DigitalOcean Personal Access Token",
			`\b(dop_v1_[a-f0-9]{64})\b`,
			[]string{},
			"?",
		},
		{
			"DigitalOcean Refresh Token",
			"DigitalOcean Refresh Token",
			`\b(dor_v1_[a-f0-9]{64})\b`,
			[]string{},
			"?",
		},
		{
			"Docker Hub Personal Access Token",
			"Docker Hub Personal Access Token",
			`\b(dckr_pat_[a-zA-Z0-9_-]{27})(?:$|[^a-zA-Z0-9_-])`,
			[]string{},
			"?",
		},
		{
			"Dropbox Short-lived access token",
			"Dropbox Short-lived access token",
			`\b(sl\.[a-zA-Z0-9_-]{130,152})(?:$|[^a-zA-Z0-9_-])`,
			[]string{},
			"?",
		},
		{
			"Figma Personal Access Token",
			"Figma Personal Access Token",
			`(?i)figma.{0,20}\b([0-9a-f]{4}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			[]string{},
			"?",
		},
		{
			"Grafana API Token",
			"Grafana API Token",
			`\b(eyJrIjoi[A-Za-z0-9]{60,100})\b`,
			[]string{},
			"?",
		},
		{
			"Grafana Cloud API Token",
			"Grafana Cloud API Token",
			`\b(glc_eyJrIjoi[A-Za-z0-9]{60,100})\b`,
			[]string{},
			"?",
		},
	}
	return regexes
}

// RemoveDuplicateSecrets removes duplicate secrets from the given slice
func RemoveDuplicateSecrets(secrets []SecretMatched) []SecretMatched {
	var uniqueSecrets []SecretMatched
	seen := make(map[string]bool)

	for _, secret := range secrets {
		// Create a unique key for each secret based on name and match
		key := secret.Secret.Name + ":" + secret.Match
		if !seen[key] {
			seen[key] = true
			uniqueSecrets = append(uniqueSecrets, secret)
		}
	}

	return uniqueSecrets
}
