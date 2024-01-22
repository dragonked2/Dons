import os, requests, difflib, logging, urllib3, asyncio, re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

regex_patterns = {
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Artifactory API Token": r'(?:\s|=|:|^|"|&)AKC[a-zA-Z0-9]{10,}',
    "Cloudinary API Key": r"cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+",
    "Firebase API Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Email Address": r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z.-]+",
    "PGP Private Key Block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "SSH Private Key": r"-----BEGIN (?:DSA|EC|OPENSSH|RSA) PRIVATE KEY-----",
    "SSH (ssh-ed25519) Public Key": r"ssh-ed25519",
    "Amazon AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Authorization Bearer Token": r"bearer [a-zA-Z0-9_\\-\\.=]+",
    "Authorization Basic Credentials": r"basic [a-zA-Z0-9=:_\+\/-]{5,100}",
    "JWT Token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook App ID": r"(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}",
    "Google Cloud Platform API Key": r"(?i)\bAIza[0-9A-Za-z\\-_]{35}\b",
    "Google Cloud Platform OAuth Token": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Twitter Access Token": r"(?i)twitter.*['|\"][0-9a-z]{35,44}['|\"]",
    "Windows Live API Key": r"(?i)windowslive.*['|\"][0-9a-f]{22}['|\"]",
    "Bitcoin Private Key (WIF)": r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$",
    "Ethereum Private Key": r"0x[a-fA-F0-9]{64}",
    "Ripple Secret Key": r"s[a-zA-Z0-9]{53}$",
    "Litecoin Private Key (WIF)": r"[LK][1-9A-HJ-NP-Za-km-z]{50}$",
    "Bitcoin Cash Private Key (WIF)": r"[Kk][1-9A-HJ-NP-Za-km-z]{50,51}$",
    "Cardano Extended Private Key": r"xprv[a-zA-Z0-9]{182}$",
    "Monero Private Spend Key": r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}",
    "Monero Private View Key": r"9[1-9A-HJ-NP-Za-km-z]{94}",
    "Zcash Private Key": r"sk[a-zA-Z0-9]{95}$",
    "Tezos Secret Key": r"edsk[a-zA-Z0-9]{54}$",
    "EOS Private Key": r"5[a-zA-Z0-9]{50}$",
    "Stellar Secret Key": r"S[a-zA-Z0-9]{55}$",
    "NEO Private Key": r"K[a-zA-Z0-9]{51}$",
    "IOTA Seed": r"[A-Z9]{81}",
    "Tron Private Key": r"0x[a-fA-F0-9]{64}",
    "VeChain Private Key": r"0x[a-fA-F0-9]{64}",
    "NEAR Protocol Private Key": r"ed25519:[a-zA-Z0-9+/]{43}==$",
    "Avalanche Private Key": r"PrivateKey-[a-zA-Z0-9]{58}",
    "Polkadot Private Key": r"0x[a-fA-F0-9]{64}",
    "Chainlink Private Key": r"0x[a-fA-F0-9]{64}",
    "Cosmos Private Key": r"0x[a-fA-F0-9]{64}",
    "Filecoin Private Key": r"f1[a-zA-Z0-9]{98}$",
    "Algorand Private Key": r"([A-Z2-7]{58})",
    "Solana Private Key": r"seed_[a-zA-Z0-9]{58}",
    "Terra Private Key": r"terravaloper[a-zA-Z0-9]{39}$",
    "Polygon (Matic) Private Key": r"0x[a-fA-F0-9]{64}",
    "Binance Smart Chain Private Key": r"0x[a-fA-F0-9]{64}",
    "Hedera Hashgraph Private Key": r"302e020100300506032b657004220420[a-fA-F0-9]{64}300506032b657001020420[a-fA-F0-9]{64}$",
    "Wanchain Private Key": r"0x[a-fA-F0-9]{64}",
    "Kusama Private Key": r"0x[a-fA-F0-9]{64}",
    "BitShares Private Key": r"BTS[a-zA-Z0-9]{50}",
    "EOSIO Key": r"EOS[a-zA-Z0-9]{50}",
    "IOST Private Key": r"0x[a-fA-F0-9]{64}",
    "Steem Private Key": r"5[a-zA-Z0-9]{50}",
    "Harmony (ONE) Private Key": r"one1[a-zA-Z0-9]{38}$",
    "Ardor Private Key": r"S[a-zA-Z0-9]{35}$",
    "Decred Private Key": r"Ds[a-zA-Z0-9]{32}$",
    "Qtum Private Key": r"0x[a-fA-F0-9]{64}",
    "Horizen Private Key": r"zn[a-zA-Z0-9]{38}$",
    "NEO Private Key": r"A[a-zA-Z0-9]{33}$",
    "Ontology Private Key": r"A[a-zA-Z0-9]{32}$",
    "Waves Private Key": r"3[a-zA-Z0-9]{35}$",
    "Nano Private Key": r"xrb_[a-zA-Z0-9]{60}$",
    "IOTEX Private Key": r"io1[a-zA-Z0-9]{41}$",
    "ICON Private Key": r"hx[a-zA-Z0-9]{40}$",
    "VeThor Private Key": r"0x[a-fA-F0-9]{64}",
    "Zilliqa Private Key": r"zil[a-zA-Z0-9]{39}$",
    "Kava Private Key": r"0x[a-fA-F0-9]{64}",
    "Elrond Private Key": r"erd1[a-zA-Z0-9]{58}$",
    "Harmony (ONE) BLS Key": r"one1p[a-zA-Z0-9]{55}$",
    "Celo Private Key": r"0x[a-fA-F0-9]{64}",
    "Flow Private Key": r"0x[a-fA-F0-9]{64}",
    "Stacks (STX) Private Key": r"0x[a-fA-F0-9]{64}",
    "Solana SPL Token Account Address": r"0x[a-fA-F0-9]{64}",
    "Aavegotchi Baazaar NFT Owner": r"0x[a-fA-F0-9]{64}",
    "Decentraland (MANA) Token ID": r"0x[a-fA-F0-9]{64}",
    "Uniswap LP Token": r"0x[a-fA-F0-9]{64}",
    "Curve.fi LP Token": r"0x[a-fA-F0-9]{64}",
    "SushiSwap LP Token": r"0x[a-fA-F0-9]{64}",
    "Balancer LP Token": r"0x[a-fA-F0-9]{64}",
    "1inch LP Token": r"0x[a-fA-F0-9]{64}",
    "Synthetix sUSD LP Token": r"0x[a-fA-F0-9]{64}",
    "Compound cToken Address": r"0x[a-fA-F0-9]{64}",
    "MakerDAO Vault Address": r"0x[a-fA-F0-9]{64}",
    "Yearn Finance Vault Address": r"0x[a-fA-F0-9]{64}",
    "Curve.fi Pool Address": r"0x[a-fA-F0-9]{64}",
    "SushiSwap MasterChef Address": r"0x[a-fA-F0-9]{64}",
    "Uniswap Router Address": r"0x[a-fA-F0-9]{64}",
    "Aave Protocol Address": r"0x[a-fA-F0-9]{64}",
    "Compound Protocol Address": r"0x[a-fA-F0-9]{64}",
    "Synthetix Protocol Address": r"0x[a-fA-F0-9]{64}",
    "Yearn Finance Protocol Address": r"0x[a-fA-F0-9]{64}",
    "Microsoft API Key": r"(?i)microsoft.*['|\"][0-9a-f]{22}['|\"]",
    "YouTube API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Reddit Client ID": r"(?i)reddit(.{0,20})?['\"][0-9a-zA-Z-_]{14}['\"]",
    "Instagram Access Token": r"(?i)instagram(.{0,20})?['\"][0-9a-zA-Z-_]{7}['\"]",
    "Docker Registry Token": r"(?i)docker[^\s]*?['|\"]\w{32,64}['|\"]",
    "GitLab Personal Access Token": r"(?i)gitlab.*['|\"]\w{20,40}['|\"]",
    "JIRA API Token": r"(?i)jira.*['|\"]\w{16}['|\"]",
    "Azure Key Vault Secret Identifier": r"https:\/\/[a-z0-9-]+\.vault\.azure\.net\/secrets\/[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+",
    "Trello API Key": r"(?i)trello.*['|\"]\w{32}['|\"]",
    "Atlassian API Key": r"(?i)atlassian.*['|\"]\w{32}['|\"]",
    "OAuth 2.0 Bearer Token": r"(?i)bearer[^\s]*?['|\"]\w{32,64}['|\"]",
    "Shopify API Key": r"(?i)shopify.*['|\"]\w{32}['|\"]",
    "Zendesk API Token": r"(?i)zendesk.*['|\"]\w{40}['|\"]",
    "GitLab OAuth Token": r"(?i)gitlab.*['|\"]\w{20,40}['|\"]",
    "Bitbucket OAuth Token": r"(?i)bitbucket.*['|\"]\w{20,40}['|\"]",
    "Discord Bot Token": r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}",
    "Discord OAuth Token": r"(?i)discord.*['|\"]\w{59}['|\"]",
    "NPM Token": r"(?i)npm[_]?token.*['|\"]\w{64}['|\"]",
    "Confluence API Token": r"(?i)confluence.*['|\"]\w{10}['|\"]",
    "CircleCI API Token": r"(?i)circleci.*['|\"]\w{40}['|\"]",
    "Hootsuite API Token": r"(?i)hootsuite.*['|\"]\w{12}['|\"]",
    "Sentry API Key": r"(?i)sentry.*['|\"]\w{32}['|\"]",
    "Mailjet API Token": r"(\w{32}-\w{13})",
    "Twitch Client ID": r"(?i)twitch(.{0,20})?['\"][0-9a-z]{30}['\"]",
    "Twitch OAuth Token": r"oauth:[a-z0-9]+",
    "Shopify OAuth Token": r"(?i)shopify.*['|\"]\w{20}['|\"]",
    "Zendesk OAuth Token": r"(?i)zendesk.*['|\"]\w{20}['|\"]",
    "Salesforce OAuth Token": r"(?i)salesforce.*['|\"]\w{300}['|\"]",
    "Atlassian OAuth Token": r"(?i)atlassian.*['|\"]\w{300}['|\"]",
    "Stripe Connect OAuth Token": r"(?i)stripe.*['|\"]sk_acct_[0-9a-zA-Z]{24}['|\"]",
    "Yammer OAuth Token": r"(?i)yammer.*['|\"]\w{48}['|\"]",
    "Coinbase OAuth Token": r"(?i)coinbase.*['|\"]\w{45}['|\"]",
    "Microsoft Office 365 API Token": r"(?i)microsoft.*['|\"]\w{360}['|\"]",
    "Pinterest OAuth Token": r"(?i)pinterest.*['|\"]\w{32}['|\"]",
    "Salesforce API Token": r"(?i)salesforce.*['|\"]\w{300}['|\"]",
    "Stripe Connect API Token": r"(?i)stripe.*['|\"]rk_acct_[0-9a-zA-Z]{24}['|\"]",
    "Yammer API Token": r"(?i)yammer.*['|\"]\w{48}['|\"]",
    "Facebook App Token": r"(?i)facebook.*['|\"]\w{140}['|\"]",
    "Yelp Fusion API Key": r"(?i)yelp.*['|\"]\w{32}['|\"]",
    "GitKraken OAuth Token": r"(?i)gitkraken.*['|\"]\w{64}['|\"]",
    "Dropbox API Token": r"(?i)dropbox.*['|\"]\w{64}['|\"]",
    "Auth0 API Token": r"(?i)auth0.*['|\"]\w{16}['|\"]",
    "Wix API Key": r"(?i)wix.*['|\"]\w{32}['|\"]",
    "Okta API Token": r"(?i)okta.*['|\"]\w{50}['|\"]",
    "Keybase PGP Key": r"(?i)keybase.*['|\"]\w{64}['|\"]",
    "HashiCorp Vault Token": r"(?i)vault.*['|\"]\w{64}['|\"]",
    "Twilio Auth Token": r"(?i)twilio.*['|\"]\w{32}['|\"]",
    "PagerDuty API Key": r"(?i)pagerduty.*['|\"]\w{20}['|\"]",
    "SendGrid API Key": r"(?i)sendgrid.*['|\"]\w{68}['|\"]",
    "Mixpanel API Key": r"(?i)mixpanel.*['|\"]\w{32}['|\"]",
    "AWS Cognito ID Token": r"(?i)cognito.*['|\"]\w{115}['|\"]",
    "AWS Cognito Refresh Token": r"(?i)cognito.*['|\"]\w{110}['|\"]",
    "Apache Kafka API Key": r"(?i)kafka.*['|\"]\w{32}['|\"]",
    "Splunk API Token": r"(?i)splunk.*['|\"]\w{64}['|\"]",
    "OneLogin API Token": r"(?i)onelogin.*['|\"]\w{40}['|\"]",
    "Auth0 Client Secret": r"(?i)auth0.*['|\"]\w{40}['|\"]",
    "PubNub API Key": r"(?i)pubnub.*['|\"]\w{40}['|\"]",
    "Fortnite Client ID": r"(?i)fortnite.*['|\"]\w{32}['|\"]",
    "Fortnite Client Secret": r"(?i)fortnite.*['|\"]\w{64}['|\"]",
    "Duo API Key": r"(?i)duo.*['|\"]\w{40}['|\"]",
    "Mapbox API Token": r"(?i)mapbox.*['|\"]\w{32}['|\"]",
    "Nordic APIs API Key": r"(?i)nordicapis.*['|\"]\w{24}['|\"]",
    "Stoplight API Key": r"(?i)stoplight.*['|\"]\w{36}['|\"]",
    "42Crunch API Key": r"(?i)42crunch.*['|\"]\w{64}['|\"]",
    "Prometheus API Key": r"(?i)prometheus.*['|\"]\w{16}['|\"]",
    "Clarifai API Key": r"(?i)clarifai.*['|\"]\w{24}['|\"]",
    "Twillio API Key": r"(?i)twillio.*['|\"]\w{32}['|\"]",
    "Quandl API Key": r"(?i)quandl.*['|\"]\w{20}['|\"]",
    "World Weather Online API Key": r"(?i)worldweatheronline.*['|\"]\w{20}['|\"]",
    "Airtable API Key": r"(?i)airtable.*['|\"]\w{40}['|\"]",
    "Bitly Generic Access Token": r"(?i)bitly.*['|\"]\w{40}['|\"]",
    "Dropbox App Key": r"(?i)dropbox.*['|\"]\w{40}['|\"]",
    "Elasticsearch Authentication": r"(?i)elasticsearch.*['|\"]\w{64}['|\"]",
    "JIRA API Key": r"(?i)jira.*['|\"]\w{16}['|\"]",
    "SendinBlue API Key": r"(?i)sendinblue.*['|\"]\w{64}['|\"]",
    "Zoho API Key": r"(?i)zoho.*['|\"]\w{32}['|\"]",
    "SoundCloud API Key": r"(?i)soundcloud.*['|\"]\w{32}['|\"]",
    "Yandex Disk OAuth Token": r"(?i)yandex.*['|\"]\w{52}['|\"]",
    "Asana Access Token": r"(?i)asana.*['|\"]\w{64}['|\"]",
    "Heroku API Key": r"(?i)heroku.*['|\"]\w{32}['|\"]",
    "Digital Ocean Spaces Access Key": r"(?i)digitalocean.*['|\"]\w{20}['|\"]",
    "Buildkite API Token": r"(?i)buildkite.*['|\"]\w{40}['|\"]",
    "Elastic Email API Key": r"(?i)elasticemail.*['|\"]\w{36}['|\"]",
    "OpenWeatherMap API Key": r"(?i)openweathermap.*['|\"]\w{32}['|\"]",
    "Pusher App Key": r"(?i)pusher.*['|\"]\w{64}['|\"]",
    "Twilio API Key": r"(?i)twilio.*['|\"]\w{32}['|\"]",
    "Mandrill API Key": r"(?i)mandrill.*['|\"]\w{42}['|\"]",
    "Intercom API Key": r"(?i)intercom.*['|\"]\w{64}['|\"]",
    "Shopify Storefront Access Token": r"(?i)shopify.*['|\"]\w{35}['|\"]",
    "Vimeo OAuth Token": r"(?i)vimeo.*['|\"]\w{40}['|\"]",
    "Mailgun API Key": r"(?i)mailgun.*['|\"]\w{32}['|\"]",
    "Zendesk OAuth Token": r"(?i)zendesk.*['|\"]\w{40}['|\"]",
    "PubNub API Key": r"(?i)pubnub.*['|\"]\w{32}['|\"]",
    "Nexmo API Key": r"(?i)nexmo.*['|\"]\w{32}['|\"]",
    "Spotify Client ID": r"(?i)spotify.*['|\"]\w{32}['|\"]",
    "Stripe API Key": r"(?i)stripe.*['|\"]\w{24}['|\"]",
    "Bit.ly Generic Access Token": r"(?i)bitly.*['|\"]\w{34}['|\"]",
    "Braintree API Key": r"(?i)braintree.*['|\"]\w{32}['|\"]",
    "Coinbase API Key": r"(?i)coinbase.*['|\"]\w{32}['|\"]",
    "Splunk API Key": r"(?i)splunk.*['|\"]\w{64}['|\"]",
    "AWS IAM Secret Key": r"(?i)aws.*['|\"]\w{40}['|\"]",
    "Firebase Cloud Messaging (FCM) Key": r"AAAA[a-zA-Z0-9_-]{140,340}",
    "API Token": r"['|\"]?api[_]?key['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Access Token": r"['|\"]?access[_]?token['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Client Secret": r"['|\"]?client[_]?secret['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "API Secret": r"['|\"]?api[_]?secret['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Session Token": r"['|\"]?session[_]?token['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Refresh Token": r"['|\"]?refresh[_]?token['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Secret Key": r"['|\"]?secret[_]?key['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "DB Connection String": r"['|\"]?connection[_]?string['|\"]?\s*[:=]\s*['|\"]?([^'\"]+)['|\"]?",
    "Database URL": r"['|\"]?database[_]?url['|\"]?\s*[:=]\s*['|\"]?([^'\"]+)['|\"]?",
    "Database Password": r"['|\"]?database[_]?password['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Database User": r"['|\"]?database[_]?user['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Database Host": r"['|\"]?database[_]?host['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Database Port": r"['|\"]?database[_]?port['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Bitcoin Private Key (Extended Key)": r"xprv[a-zA-Z0-9]{107}$|xpub[a-zA-Z0-9]{107}$",
    "Ethereum Private Key (Extended Key)": r"xprv[a-zA-Z0-9]{107}$|xpub[a-zA-Z0-9]{107}$",
    "Zcash Transparent Address": r"t1[a-zA-Z0-9]{33}$",
    "Tezos Public Key": r"tz[1-9A-HJ-NP-Za-km-z]{34}$",
    "Cardano Extended Public Key": r"xpub[a-zA-Z0-9]{182}$",
    "EOS Account Name": r"[a-z1-5]{1,12}$",
    "Stellar Account ID": r"G[a-zA-Z0-9]{54}$",
    "NEO Wallet Address": r"A[a-zA-Z0-9]{33}$",
    "IOTA Address": r"[A-Z9]{90}",
    "Ripple Address": r"r[a-zA-Z0-9]{33}$",
    "SSH Private Key (DSA)": r"-----BEGIN DSA PRIVATE KEY-----[a-zA-Z0-9/+=]+-----END DSA PRIVATE KEY-----",
    "SSH Private Key (ECDSA)": r"-----BEGIN EC PRIVATE KEY-----[a-zA-Z0-9/+=]+-----END EC PRIVATE KEY-----",
    "SSH Private Key (Ed25519)": r"-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9/+=]+-----END OPENSSH PRIVATE KEY-----",
    "BitLocker Recovery Key": r"[0-9BCDFGHJKMPQRTVWXY]{6}-[0-9BCDFGHJKMPQRTVWXY]{6}-[0-9BCDFGHJKMPQRTVWXY]{6}-[0-9BCDFGHJKMPQRTVWXY]{6}-[0-9BCDFGHJKMPQRTVWXY]{6}",
    "VeraCrypt Recovery Key": r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}",
    "TrueCrypt Volume Keyfile": r"[0-9A-Fa-f]{64}.keyfile",
    "GPG Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----[a-zA-Z0-9/+=]+-----END PGP PRIVATE KEY BLOCK-----",
    "Android Keystore Key": r"-----BEGIN (?:.*\n)*.*ENCRYPTED PRIVATE KEY(?:.*\n)+.*-----END (?:.*\n)*",
    "Windows Credential Manager Entry": r"\[.*\]\nUsername=.*\nPassword=.*\n",
    "KeePass Database Master Key": r"Database Master Key: .*",
    "Slack Token": r"(?i)slack.*['|\"]xox[baprs]-\w{12}-\w{12}-\w{12}['|\"]",
    "Git Token": r"(?i)git.*['|\"]\w{40}['|\"]",
    "Tinder API Token": r"(?i)tinder.*['|\"]\w{32}['|\"]",
    "Jenkins API Token": r"(?i)jenkins.*['|\"]\w{32}['|\"]",
    "PagerDuty Integration Key": r"(?i)pdintegration.*['|\"]\w{32}['|\"]",
    "Docker Hub Token": r"(?i)dockerhub.*['|\"]\w{32}['|\"]",
    "JFrog Artifactory API Key": r"(?i)artifactory.*['|\"]\w{40}['|\"]",
    "Kubernetes Config File": r"(?i)apiVersion: v1.*kind: Config",
    "Hashicorp Consul Token": r"(?i)consul.*['|\"]\w{16}['|\"]",
    "Datadog API Key": r"(?i)datadog.*['|\"]\w{32}['|\"]",
    "Dynatrace API Token": r"(?i)dynatrace.*['|\"]\w{32}['|\"]",
    "New Relic API Key": r"(?i)newrelic.*['|\"]\w{40}['|\"]",
    "Splunk HEC Token": r"(?i)splunk.*token\s*:\s*['|\"]\w{32}['|\"]",
    "Puppet Forge API Token": r"(?i)puppet.*['|\"]\w{64}['|\"]",
    "Azure Service Principal Client Secret": r"(?i)azure.*client\s*secret\s*=\s*['|\"]\w{44}['|\"]",
    "Azure Storage Account Key": r"(?i)azure.*storageaccountkey\s*=\s*['|\"]\w{88}==['|\"]",
    "Azure Cosmos DB Primary Key": r"(?i)azure.*primary\s*key\s*=\s*['|\"]\w{64}['|\"]",
    "Azure SAS Token": r"(?i)azure.*sas\s*=\s*['|\"]\w{32}['|\"]",
    "AWS S3 Access Key": r"(?i)aws.*s3.*access\s*key\s*=\s*['|\"]\w{20}['|\"]",
    "AWS S3 Secret Key": r"(?i)aws.*s3.*secret\s*key\s*=\s*['|\"]\w{40}['|\"]",
    "AWS Lambda Function Key": r"(?i)aws.*lambda.*function.*key\s*=\s*['|\"]\w{30}['|\"]",
    "IBM Cloud API Key": r"(?i)ibm.*api.*key\s*:\s*['|\"]\w{44}['|\"]",
    "IBM Cloud IAM API Key": r"(?i)ibm.*iam.*api.*key\s*:\s*['|\"]\w{44}['|\"]",
    "Jupyter Notebook Token": r"(?i)jupyter.*token\s*=\s*['|\"]\w{32}['|\"]",
    "AWS Elastic Beanstalk API Key": r"(?i)aws.*elasticbeanstalk.*api.*key\s*=\s*['|\"]\w{20}['|\"]",
    "Google Cloud Service Account Key": r"(?i)google.*service.*account.*key\s*:\s*['|\"]\w{88}['|\"]",
    "Google Cloud Firestore API Key": r"(?i)google.*firestore.*api.*key\s*=\s*['|\"]\w{40}['|\"]",
    "Google Cloud Storage API Key": r"(?i)google.*storage.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Speech API Key": r"(?i)google.*speech.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Vision API Key": r"(?i)google.*vision.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Translation API Key": r"(?i)google.*translation.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Natural Language API Key": r"(?i)google.*language.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Video Intelligence API Key": r"(?i)google.*video.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Datastore API Key": r"(?i)google.*datastore.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud BigQuery API Key": r"(?i)google.*bigquery.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Dataproc API Key": r"(?i)google.*dataproc.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Pub/Sub API Key": r"(?i)google.*pubsub.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Spanner API Key": r"(?i)google.*spanner.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Compute Engine API Key": r"(?i)google.*compute.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Dialogflow API Key": r"(?i)google.*dialogflow.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase Realtime Database API Key": r"(?i)google.*firebase.*realtime.*database.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase Cloud Messaging (FCM) API Key": r"(?i)google.*firebase.*cloud.*messaging.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase Authentication API Key": r"(?i)google.*firebase.*authentication.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase Hosting API Key": r"(?i)google.*firebase.*hosting.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase Test Lab API Key": r"(?i)google.*firebase.*test.*lab.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase Remote Config API Key": r"(?i)google.*firebase.*remote.*config.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase In-App Messaging API Key": r"(?i)google.*firebase.*in.*app.*messaging.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase Dynamic Links API Key": r"(?i)google.*firebase.*dynamic.*links.*api.*key\s*=\s*['|\"]\w{39}['|\"]",
    "Google Cloud Firebase Realtime Database URL": r"(?i)google.*firebase.*realtime.*database.*url\s*=\s*['|\"]https:\/\/[a-zA-Z0-9-]+\.firebaseio\.com['|\"]",
    "Google Cloud Firebase Project ID": r"(?i)google.*firebase.*project.*id\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Storage Bucket": r"(?i)google.*firebase.*storage.*bucket\s*=\s*['|\"]\w+\.appspot\.com['|\"]",
    "Google Cloud Firebase Default Cloud Storage Bucket": r"(?i)google.*firebase.*default.*cloud.*storage.*bucket\s*=\s*['|\"]\w+\.appspot\.com['|\"]",
    "Google Cloud Firebase Default Realtime Database Instance": r"(?i)google.*firebase.*default.*realtime.*database.*instance\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Cloud Storage Instance": r"(?i)google.*firebase.*default.*cloud.*storage.*instance\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Cloud Storage Host": r"(?i)google.*firebase.*default.*cloud.*storage.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]",
    "Google Cloud Firebase Default Cloud Storage Base URL": r"(?i)google.*firebase.*default.*cloud.*storage.*base.*url\s*=\s*['|\"]https:\/\/\w+\.appspot\.com['|\"]",
    "Google Cloud Firebase Default Cloud Storage Path": r"(?i)google.*firebase.*default.*cloud.*storage.*path\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Cloud Storage Requester Pays": r"(?i)google.*firebase.*default.*cloud.*storage.*requester.*pays\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Cloud Storage User Project": r"(?i)google.*firebase.*default.*cloud.*storage.*user.*project\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Firestore Project ID": r"(?i)google.*firebase.*default.*firestore.*project.*id\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Firestore Database ID": r"(?i)google.*firebase.*default.*firestore.*database.*id\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Firestore Collection ID": r"(?i)google.*firebase.*default.*firestore.*collection.*id\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Firestore Document ID": r"(?i)google.*firebase.*default.*firestore.*document.*id\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Firestore Storage Bucket": r"(?i)google.*firebase.*default.*firestore.*storage.*bucket\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Firestore Host": r"(?i)google.*firebase.*default.*firestore.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]",
    "Google Cloud Firebase Default Firestore Base URL": r"(?i)google.*firebase.*default.*firestore.*base.*url\s*=\s*['|\"]https:\/\/\w+\.appspot\.com['|\"]",
    "Google Cloud Firebase Default Firestore Path": r"(?i)google.*firebase.*default.*firestore.*path\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Firestore User Project": r"(?i)google.*firebase.*default.*firestore.*user.*project\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firebase Default Firestore Emulator Host": r"(?i)google.*firebase.*default.*firestore.*emulator.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]",
    "Google Cloud Firestore Rules File": r"(?i)google.*firestore.*rules\s*=\s*['|\"].*\.rules['|\"]",
    "Google Cloud Firestore Indexes File": r"(?i)google.*firestore.*indexes\s*=\s*['|\"].*\.json['|\"]",
    "Google Cloud Firestore Emulator Rules File": r"(?i)google.*firestore.*emulator.*rules\s*=\s*['|\"].*\.rules['|\"]",
    "Google Cloud Firestore Emulator Indexes File": r"(?i)google.*firestore.*emulator.*indexes\s*=\s*['|\"].*\.json['|\"]",
    "Google Cloud Firestore Emulator Host": r"(?i)google.*firestore.*emulator.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]",
    "Google Cloud Firestore Emulator Port": r"(?i)google.*firestore.*emulator.*port\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firestore Emulator Auto Download": r"(?i)google.*firestore.*emulator.*auto.*download\s*=\s*['|\"]\w+['|\"]",
    "Google Cloud Firestore Emulator Host and Port": r"(?i)google.*firestore.*emulator.*host.*port\s*=\s*['|\"]\w+\.appspot\.com:\w+['|\"]",
    "Google Cloud Pub/Sub Emulator Host": r"(?i)google.*pubsub.*emulator.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]",

}


class WebsiteScanner:
    DEFAULT_DEPTH = 4

    def __init__(self, depth=None):
        self.depth = depth or self.DEFAULT_DEPTH
        self.results = set()
        self.logger = logging.getLogger(__name__)
        self.matches_file_path = os.path.join(os.path.expanduser("~"), "Desktop", "matches.txt")

    def is_same_domain(self, base_url, target_url):
        return urlparse(base_url).netloc == urlparse(target_url).netloc

    def get_urls_from_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file.readlines()]
        except FileNotFoundError as e:
            self.logger.error(f"File not found: {file_path}")
            raise e

    def crawl_and_scan(self, url, base_url):
        if self.depth <= 0 or not self.is_same_domain(base_url, url):
            return

        try:
            response = self.fetch(url)
            if response.status_code == 403:
                self.logger.warning(f"Skipping {url} due to 403 Forbidden error")
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            js_urls = [urljoin(url, script['src']) for script in soup.find_all('script', src=True)]

            with ThreadPoolExecutor() as executor:
                results = [self.scan_js_file(js_url) for js_url in js_urls]

            unique_results = self.cluster_matches(results)
            for js_url, matches in unique_results:
                result_key = (js_url, tuple(matches))
                if result_key not in self.results:
                    self.results.add(result_key)
                    self.save_and_display_matches(url, js_url, matches)

            next_depth_urls = [urljoin(url, link['href']) for link in soup.find_all('a', href=True)]
            for u in next_depth_urls:
                self.crawl_and_scan(u, url)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error accessing {url}: {e}")
        except Exception as ex:
            self.logger.error(f"An unexpected error occurred: {ex}")

    def scan_js_file(self, js_url):
        try:
            response = self.fetch(js_url)
            response.raise_for_status()

            js_content = response.text
            matches = []

            for key, pattern in regex_patterns.items():
                match_objects = re.finditer(pattern, js_content)
                for match in match_objects:
                    matches.append((key, match.group(0).strip()))

            return js_url, matches

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error accessing {js_url}: {e}")
            return js_url, []
        except Exception as ex:
            self.logger.error(f"An unexpected error occurred while scanning {js_url}: {ex}")
            return js_url, []

    def fetch(self, url):
        return requests.get(url, verify=False, timeout=10)

    def save_and_display_matches(self, website_url, js_url, matches):
        with open(self.matches_file_path, 'a', encoding='utf-8') as file:
            file.write(f"\nMatches found at {website_url}, JavaScript file: {js_url}:\n")

            if matches:
                for key, snippet in matches:
                    file.write(f"  Key: {key}\n")
                    file.write(f"    Snippet: {snippet}\n" if snippet else f"    Snippet: [Unable to retrieve snippet]\n")
            else:
                file.write("  No matches found.\n")

        self.logger.info(colored(f"\nMatches found at {website_url}, JavaScript file: {js_url}:", 'green'))

        if matches:
            for key, snippet in matches:
                self.logger.info(colored(f"  Key: {key}", 'cyan'))
                self.logger.info(colored(f"    Snippet: {snippet}\n" if snippet else f"    Snippet: [Unable to retrieve snippet]", 'yellow'))
        else:
            self.logger.info(colored("  No matches found.", 'red'))

    def cluster_matches(self, results):
        clustered_results = {}
        for js_url, matches in results:
            if js_url not in clustered_results:
                clustered_results[js_url] = matches
            else:
                for key, snippet in matches:
                    found = any(self.calculate_similarity(existing_snippet, snippet) > 90 for _, existing_snippet in clustered_results[js_url])
                    if not found:
                        clustered_results[js_url].append((key, snippet))

        return list(clustered_results.items())

    def calculate_similarity(self, str1, str2):
        seq_matcher = difflib.SequenceMatcher(None, str1, str2)
        return seq_matcher.ratio() * 100

    def scan_websites(self, websites):
        for website in tqdm(websites, desc="Scanning websites", position=1):
            self.crawl_and_scan(website, website)

def setup_logging():
    logging.basicConfig(level=logging.INFO)

def main():
    try:
        setup_logging()

        file_or_single = input(colored("Scan multiple websites from a file or a single website? (Enter 'file' or 'single'): ", 'yellow')).lower()

        websites = []
        if file_or_single in ['file', 'single']:
            try:
                websites = WebsiteScanner().get_urls_from_file(input(colored("Enter the path to the file containing website URLs: ", 'yellow'))) if file_or_single == 'file' else [input(colored("Enter the website URL: ", 'yellow'))]
            except FileNotFoundError:
                logging.error("File not found. Exiting.")
                return
        else:
            logging.error("Invalid input. Exiting.")
            return

        try:
            depth = max(0, int(input(colored(f"Enter the recursive depth for scanning (default is {WebsiteScanner.DEFAULT_DEPTH}): ", 'yellow')) or WebsiteScanner.DEFAULT_DEPTH))
        except ValueError as ve:
            logging.error(f"Invalid depth value: {ve}. Using default depth.")
            depth = WebsiteScanner.DEFAULT_DEPTH

        print(colored(f"\nScanning {len(websites)} website(s) with recursive depth of {depth}...\n", 'cyan'))

        scanner = WebsiteScanner(depth)
        scanner.scan_websites(websites)

        print(colored("\nScan completed successfully.", 'green'))

    except KeyboardInterrupt:
        print(colored("\nScan aborted by the user.", 'yellow'))
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()

