import os
import re
import asyncio
import logging
import base64
import json
import aiohttp
from pathlib import Path
from typing import List, Tuple, Set, Optional
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlsplit, parse_qs
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich.status import Status
from rich.text import Text
from bs4 import BeautifulSoup
from aiohttp import ClientSession, ClientTimeout, TCPConnector

# Initialize Rich console with markup and emoji support
console = Console(highlight=True, emoji=True)

# Animated Banner with Rich's console typing effect
banner = """
▀███▀▀▀██▄                             
  ██    ▀██▄                           
  ██     ▀██ ▄██▀██▄▀████████▄  ▄██▀███
  ██      ████▀   ▀██ ██    ██  ██   ▀▀
  ██     ▄████     ██ ██    ██  ▀█████▄
  ██    ▄██▀██▄   ▄██ ██    ██  █▄   ██
▄████████▀   ▀█████▀▄████  ████▄██████▀
By Ali Essam
"""    

# Display the banner with a typing effect
console.print(Text(banner, style="bold blue"), end="")

@dataclass(frozen=True)
class ScanMatch:
    key: str
    snippet: str
    context: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None


@dataclass(frozen=True)
class ScanResult:
    website_url: str
    js_url: str
    matches: Tuple[ScanMatch, ...]  # Change list to tuple for hashability
    timestamp: datetime = datetime.now()


class WebsiteScanner:
    def __init__(self, discord_webhook_url: str, depth: int, concurrency: int, timeout: int, retry_limit: int = 3):
        self.config = {
            "depth": depth,
            "concurrency": concurrency,
            "timeout": timeout,
            "retry_limit": retry_limit,
            "user_agent": "Dons JS Scanner/2.0 (Security Research)",
            "output_dir": str(Path.home() / "Desktop" / "website_scanner_results"),
            "patterns": {
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Artifactory API Token": re.compile(r'(?:\s|=|:|^|"|&)AKC[a-zA-Z0-9]{10,}'),
    "Cloudinary API Key": re.compile(r"cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+"),
    "Firebase API Key": re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
    "Email Address": re.compile(r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z.-]+"),
    "PGP Private Key Block": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    "SSH Private Key": re.compile(r"-----BEGIN (?:DSA|EC|OPENSSH|RSA) PRIVATE KEY-----"),
    "SSH (ssh-ed25519) Public Key": re.compile(r"ssh-ed25519"),
    "Amazon AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Amazon MWS Auth Token": re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "JWT Token": re.compile(r"ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*$", re.IGNORECASE),
    "Facebook Access Token": re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
    "Google Cloud Platform API Key": re.compile(r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Google Cloud Platform OAuth Token": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "Windows Live API Key": re.compile(r"(?i)windowslive.*['|\"][0-9a-f]{22}['|\"]"),
    "Bitcoin Private Key (WIF)": re.compile(r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$"),
    "Ethereum Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Ripple Secret Key": re.compile(r"s[a-zA-Z0-9]{53}$"),
    "Litecoin Private Key (WIF)": re.compile(r"[LK][1-9A-HJ-NP-Za-km-z]{50}$"),
    "Bitcoin Cash Private Key (WIF)": re.compile(r"[Kk][1-9A-HJ-NP-Za-km-z]{50,51}$"),
    "Cardano Extended Private Key": re.compile(r"xprv[a-zA-Z0-9]{182}$"),
    "Monero Private View Key": re.compile(r"9[1-9A-HJ-NP-Za-km-z]{94}"),
    "Zcash Private Key": re.compile(r"sk[a-zA-Z0-9]{95}$"),
    "Tezos Secret Key": re.compile(r"edsk[a-zA-Z0-9]{54}$"),
    "EOS Private Key": re.compile(r"5[a-zA-Z0-9]{50}$"),
    "Stellar Secret Key": re.compile(r"S[a-zA-Z0-9]{55}$"),
    "NEO Private Key": re.compile(r"K[a-zA-Z0-9]{51}$"),
    "IOTA Seed": re.compile(r"[A-Z9]{81}"),
    "Tron Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "VeChain Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "NEAR Protocol Private Key": re.compile(r"ed25519:[a-zA-Z0-9+/]{43}==$"),
    "Avalanche Private Key": re.compile(r"PrivateKey-[a-zA-Z0-9]{58}"),
    "Polkadot Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Chainlink Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Cosmos Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Filecoin Private Key": re.compile(r"f1[a-zA-Z0-9]{98}$"),
    "Solana Private Key": re.compile(r"seed_[a-zA-Z0-9]{58}"),
    "Terra Private Key": re.compile(r"terravaloper[a-zA-Z0-9]{39}$"),
    "Polygon (Matic) Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Binance Smart Chain Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Hedera Hashgraph Private Key": re.compile(r"302e020100300506032b657004220420[a-fA-F0-9]{64}300506032b657001020420[a-fA-F0-9]{64}$"),
    "Wanchain Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Kusama Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "BitShares Private Key": re.compile(r"BTS[a-zA-Z0-9]{50}"),
    "EOSIO Key": re.compile(r"EOS[a-zA-Z0-9]{50}"),
    "IOST Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Harmony (ONE) Private Key": re.compile(r"one1[a-zA-Z0-9]{38}$"),
    "Ardor Private Key": re.compile(r"S[a-zA-Z0-9]{35}$"),
    "Decred Private Key": re.compile(r"Ds[a-zA-Z0-9]{32}$"),
    "Qtum Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Horizen Private Key": re.compile(r"zn[a-zA-Z0-9]{38}$"),
    "NEO Private Key": re.compile(r"A[a-zA-Z0-9]{33}$"),
    "Ontology Private Key": re.compile(r"A[a-zA-Z0-9]{32}$"),
    "Waves Private Key": re.compile(r"3[a-zA-Z0-9]{35}$"),
    "Nano Private Key": re.compile(r"xrb_[a-zA-Z0-9]{60}$"),
    "IOTEX Private Key": re.compile(r"io1[a-zA-Z0-9]{41}$"),
    "ICON Private Key": re.compile(r"hx[a-zA-Z0-9]{40}$"),
    "VeThor Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Zilliqa Private Key": re.compile(r"zil[a-zA-Z0-9]{39}$"),
    "Kava Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Elrond Private Key": re.compile(r"erd1[a-zA-Z0-9]{58}$"),
    "Harmony (ONE) BLS Key": re.compile(r"one1p[a-zA-Z0-9]{55}$"),
    "Celo Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Flow Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Stacks (STX) Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Solana SPL Token Account Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Aavegotchi Baazaar NFT Owner": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Decentraland (MANA) Token ID": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Uniswap LP Token": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Curve.fi LP Token": re.compile(r"0x[a-fA-F0-9]{64}"),
    "SushiSwap LP Token": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Balancer LP Token": re.compile(r"0x[a-fA-F0-9]{64}"),
    "1inch LP Token": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Synthetix sUSD LP Token": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Compound cToken Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "MakerDAO Vault Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Yearn Finance Vault Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Curve.fi Pool Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "SushiSwap MasterChef Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Uniswap Router Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Aave Protocol Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Compound Protocol Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Synthetix Protocol Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Yearn Finance Protocol Address": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Microsoft API Key": re.compile(r"(?i)microsoft.*['|\"][0-9a-f]{22}['|\"]"),
    "YouTube API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Reddit Client ID": re.compile(r"(?i)reddit(.{0,20})?['\"][0-9a-zA-Z\-_]{14}['\"]"),
    "Instagram Access Token": re.compile(r"(?i)instagram(.{0,20})?['\"][0-9a-zA-Z\-_]{7}['\"]"),
    "Docker Registry Token": re.compile(r"(?i)docker[^\s]*?['|\"]\w{32,64}['|\"]"),
    "GitLab Personal Access Token": re.compile(r"(?i)gitlab.*['|\"]\w{20,40}['|\"]"),
    "Azure Key Vault Secret Identifier": re.compile(r"https:\/\/[a-z0-9\-]+\.vault\.azure\.net\/secrets\/[a-zA-Z0-9\-]+\/[a-zA-Z0-9\-]+"),
    "Trello API Key": re.compile(r"(?i)trello.*['|\"]\w{32}['|\"]"),
    "Atlassian API Key": re.compile(r"(?i)atlassian.*['|\"]\w{32}['|\"]"),
    "OAuth 2.0 Bearer Token": re.compile(r"(?i)bearer[^\s]*?['|\"]\w{32,64}['|\"]"),
    "Shopify API Key": re.compile(r"(?i)shopify.*['|\"]\w{32}['|\"]"),
    "Zendesk API Token": re.compile(r"(?i)zendesk.*['|\"]\w{40}['|\"]"),
    "GitLab OAuth Token": re.compile(r"(?i)gitlab.*['|\"]\w{20,40}['|\"]"),
    "Bitbucket OAuth Token": re.compile(r"(?i)bitbucket.*['|\"]\w{20,40}['|\"]"),
    "Discord OAuth Token": re.compile(r"(?i)discord.*['|\"]\w{59}['|\"]"),
    "NPM Token": re.compile(r"(?i)npm[_]?token.*['|\"]\w{64}['|\"]"),
    "Confluence API Token": re.compile(r"(?i)confluence.*['|\"]\w{10}['|\"]"),
    "CircleCI API Token": re.compile(r"(?i)circleci.*['|\"]\w{40}['|\"]"),
    "Hootsuite API Token": re.compile(r"(?i)hootsuite.*['|\"]\w{12}['|\"]"),
    "Twitch Client ID": re.compile(r"(?i)twitch(.{0,20})?['\"][0-9a-z]{30}['\"]"),
    "Twitch OAuth Token": re.compile(r"oauth:[a-z0-9]+", re.IGNORECASE),
    "Zendesk OAuth Token": re.compile(r"(?i)zendesk.*['|\"]\w{20}['|\"]"),
    "Salesforce OAuth Token": re.compile(r"(?i)salesforce.*['|\"]\w{300}['|\"]"),
    "Stripe Connect OAuth Token": re.compile(r"(?i)stripe.*['|\"]sk_acct_[0-9a-zA-Z]{24}['|\"]"),
    "Yammer OAuth Token": re.compile(r"(?i)yammer.*['|\"]\w{48}['|\"]"),
    "Coinbase OAuth Token": re.compile(r"(?i)coinbase.*['|\"]\w{45}['|\"]"),
    "Microsoft Office 365 API Token": re.compile(r"(?i)microsoft.*['|\"]\w{360}['|\"]"),
    "Pinterest OAuth Token": re.compile(r"(?i)pinterest.*['|\"]\w{32}['|\"]"),
    "Salesforce API Token": re.compile(r"(?i)salesforce.*['|\"]\w{300}['|\"]"),
    "Stripe Connect API Token": re.compile(r"(?i)stripe.*['|\"]rk_acct_[0-9a-zA-Z]{24}['|\"]"),
    "Yammer API Token": re.compile(r"(?i)yammer.*['|\"]\w{48}['|\"]"),
    "Facebook App Token": re.compile(r"(?i)facebook.*['|\"]\w{140}['|\"]"),
    "Yelp Fusion API Key": re.compile(r"(?i)yelp.*['|\"]\w{32}['|\"]"),
    "GitKraken OAuth Token": re.compile(r"(?i)gitkraken.*['|\"]\w{64}['|\"]"),
    "Dropbox API Token": re.compile(r"(?i)dropbox.*['|\"]\w{64}['|\"]"),
    "Auth0 API Token": re.compile(r"(?i)auth0.*['|\"]\w{16}['|\"]"),
    "Okta API Token": re.compile(r"(?i)okta.*['|\"]\w{50}['|\"]"),
    "Keybase PGP Key": re.compile(r"(?i)keybase.*['|\"]\w{64}['|\"]"),
    "HashiCorp Vault Token": re.compile(r"(?i)vault.*['|\"]\w{64}['|\"]"),
    "Twilio Auth Token": re.compile(r"(?i)twilio.*['|\"]\w{32}['|\"]"),
    "SendGrid API Key": re.compile(r"(?i)sendgrid.*['|\"]\w{68}['|\"]"),
    "Mixpanel API Key": re.compile(r"(?i)mixpanel.*['|\"]\w{32}['|\"]"),
    "AWS Cognito ID Token": re.compile(r"(?i)cognito.*['|\"]\w{115}['|\"]"),
    "AWS Cognito Refresh Token": re.compile(r"(?i)cognito.*['|\"]\w{110}['|\"]"),
    "Apache Kafka API Key": re.compile(r"(?i)kafka.*['|\"]\w{32}['|\"]"),
    "Splunk API Token": re.compile(r"(?i)splunk.*['|\"]\w{64}['|\"]"),
    "Puppet Forge API Token": re.compile(r"(?i)puppet.*['|\"]\w{64}['|\"]"),
    "Azure Service Principal Client Secret": re.compile(r"(?i)azure.*client\s*secret\s*=\s*['|\"]\w{44}['|\"]"),
    "Azure Storage Account Key": re.compile(r"(?i)azure.*storageaccountkey\s*=\s*['|\"]\w{88}==['|\"]"),
    "Azure Cosmos DB Primary Key": re.compile(r"(?i)azure.*primary\s*key\s*=\s*['|\"]\w{64}['|\"]"),
    "Azure SAS Token": re.compile(r"(?i)azure.*sas\s*=\s*['|\"]\w{32}['|\"]"),
    "AWS S3 Access Key": re.compile(r"(?i)aws.*s3.*access\s*key\s*=\s*['|\"]\w{20}['|\"]"),
    "AWS S3 Secret Key": re.compile(r"(?i)aws.*s3.*secret\s*key\s*=\s*['|\"]\w{40}['|\"]"),
    "AWS Lambda Function Key": re.compile(r"(?i)aws.*lambda.*function.*key\s*=\s*['|\"]\w{30}['|\"]"),
    "IBM Cloud API Key": re.compile(r"(?i)ibm.*api.*key\s*:\s*['|\"]\w{44}['|\"]"),
    "IBM Cloud IAM API Key": re.compile(r"(?i)ibm.*iam.*api.*key\s*:\s*['|\"]\w{44}['|\"]"),
    "Jupyter Notebook Token": re.compile(r"(?i)jupyter.*token\s*=\s*['|\"]\w{32}['|\"]"),
    "AWS Elastic Beanstalk API Key": re.compile(r"(?i)aws.*elasticbeanstalk.*api.*key\s*=\s*['|\"]\w{20}['|\"]"),
    "Google Cloud Service Account Key": re.compile(r"(?i)google.*service.*account.*key\s*:\s*['|\"]\w{88}['|\"]"),
    "Google Cloud Firestore API Key": re.compile(r"(?i)google.*firestore.*api.*key\s*=\s*['|\"]\w{40}['|\"]"),
    "Google Cloud Storage API Key": re.compile(r"(?i)google.*storage.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Speech API Key": re.compile(r"(?i)google.*speech.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Vision API Key": re.compile(r"(?i)google.*vision.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Translation API Key": re.compile(r"(?i)google.*translation.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Natural Language API Key": re.compile(r"(?i)google.*language.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Video Intelligence API Key": re.compile(r"(?i)google.*video.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Datastore API Key": re.compile(r"(?i)google.*datastore.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud BigQuery API Key": re.compile(r"(?i)google.*bigquery.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Dataproc API Key": re.compile(r"(?i)google.*dataproc.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Pub/Sub API Key": re.compile(r"(?i)google.*pubsub.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Spanner API Key": re.compile(r"(?i)google.*spanner.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Compute Engine API Key": re.compile(r"(?i)google.*compute.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Dialogflow API Key": re.compile(r"(?i)google.*dialogflow.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Realtime Database API Key": re.compile(r"(?i)google.*firebase.*realtime.*database.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Cloud Messaging (FCM) API Key": re.compile(r"(?i)google.*firebase.*cloud.*messaging.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Authentication API Key": re.compile(r"(?i)google.*firebase.*authentication.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Hosting API Key": re.compile(r"(?i)google.*firebase.*hosting.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Test Lab API Key": re.compile(r"(?i)google.*firebase.*test.*lab.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Remote Config API Key": re.compile(r"(?i)google.*firebase.*remote.*config.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase In-App Messaging API Key": re.compile(r"(?i)google.*firebase.*in.*app.*messaging.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Dynamic Links API Key": re.compile(r"(?i)google.*firebase.*dynamic.*links.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Realtime Database URL": re.compile(r"(?i)google.*firebase.*realtime.*database.*url\s*=\s*['|\"]https:\/\/[a-zA-Z0-9\-]+\.firebaseio\.com['|\"]"),
    "Google Cloud Firebase Project ID": re.compile(r"(?i)google.*firebase.*project.*id\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Storage Bucket": re.compile(r"(?i)google.*firebase.*storage.*bucket\s*=\s*['|\"]\w+\.appspot\.com['|\"]"),
    "Google Cloud Firebase Default Cloud Storage Bucket": re.compile(r"(?i)google.*firebase.*default.*cloud.*storage.*bucket\s*=\s*['|\"]\w+\.appspot\.com['|\"]"),
    "Google Cloud Firebase Default Realtime Database Instance": re.compile(r"(?i)google.*firebase.*default.*realtime.*database.*instance\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Cloud Storage Instance": re.compile(r"(?i)google.*firebase.*default.*cloud.*storage.*instance\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Cloud Storage Host": re.compile(r"(?i)google.*firebase.*default.*cloud.*storage.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]"),
    "Google Cloud Firebase Default Cloud Storage Base URL": re.compile(r"(?i)google.*firebase.*default.*cloud.*storage.*base.*url\s*=\s*['|\"]https:\/\/\w+\.appspot\.com['|\"]"),
    "Google Cloud Firebase Default Cloud Storage Path": re.compile(r"(?i)google.*firebase.*default.*cloud.*storage.*path\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Cloud Storage Requester Pays": re.compile(r"(?i)google.*firebase.*default.*cloud.*storage.*requester.*pays\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Cloud Storage User Project": re.compile(r"(?i)google.*firebase.*default.*cloud.*storage.*user.*project\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Firestore Project ID": re.compile(r"(?i)google.*firebase.*default.*firestore.*project.*id\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Firestore Database ID": re.compile(r"(?i)google.*firebase.*default.*firestore.*database.*id\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Firestore Collection ID": re.compile(r"(?i)google.*firebase.*default.*firestore.*collection.*id\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Firestore Document ID": re.compile(r"(?i)google.*firebase.*default.*firestore.*document.*id\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Firestore Storage Bucket": re.compile(r"(?i)google.*firebase.*default.*firestore.*storage.*bucket\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Firestore Host": re.compile(r"(?i)google.*firebase.*default.*firestore.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]"),
    "Google Cloud Firebase Default Firestore Base URL": re.compile(r"(?i)google.*firebase.*default.*firestore.*base.*url\s*=\s*['|\"]https:\/\/\w+\.appspot\.com['|\"]"),
    "Google Cloud Firebase Default Firestore Path": re.compile(r"(?i)google.*firebase.*default.*firestore.*path\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Firestore User Project": re.compile(r"(?i)google.*firebase.*default.*firestore.*user.*project\s*=\s*['|\"]\w+['|\"]"),
    "Google Cloud Firebase Default Firestore Emulator Host": re.compile(r"(?i)google.*firebase.*default.*firestore.*emulator.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]"),
    "Google Cloud Firestore Rules File": re.compile(r"(?i)google.*firestore.*rules\s*=\s*['|\"].*\.rules['|\"]"),
    "Google Cloud Firestore Indexes File": re.compile(r"(?i)google.*firestore.*indexes\s*=\s*['|\"].*\.json['|\"]"),
    "Google Cloud Firestore Emulator Rules File": re.compile(r"(?i)google.*firestore.*emulator.*rules\s*=\s*['|\"].*\.rules['|\"]"),
    "Google Cloud Firestore Emulator Indexes File": re.compile(r"(?i)google.*firestore.*emulator.*indexes\s*=\s*['|\"].*\.json['|\"]"),
    "Google Cloud Firestore Emulator Host": re.compile(r"(?i)google.*firestore.*emulator.*host\s*=\s*['|\"]\w+\.appspot\.com['|\"]"),
    "API Token": re.compile(r"['|\"]?api[_]?key['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "Client Secret": re.compile(r"['|\"]?client[_]?secret['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "API Secret": re.compile(r"['|\"]?api[_]?secret['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "Session Token": re.compile(r"['|\"]?session[_]?token['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "Refresh Token": re.compile(r"['|\"]?refresh[_]?token['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "Secret Key": re.compile(r"['|\"]?secret[_]?key['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "DB Connection String": re.compile(r"['|\"]?connection[_]?string['|\"]?\s*[:=]\s*['|\"]?([^'\"]+)['|\"]?"),
    "Database URL": re.compile(r"['|\"]?database[_]?url['|\"]?\s*[:=]\s*['|\"]?([^'\"]+)['|\"]?"),
    "Database Password": re.compile(r"['|\"]?database[_]?password['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "Database User": re.compile(r"['|\"]?database[_]?user['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "Database Host": re.compile(r"['|\"]?database[_]?host['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "Database Port": re.compile(r"['|\"]?database[_]?port['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9\-_.]+)['|\"]?"),
    "Bitcoin Private Key (Extended Key)": re.compile(r"xprv[a-zA-Z0-9]{107}$|xpub[a-zA-Z0-9]{107}$"),
    "Ethereum Private Key (Extended Key)": re.compile(r"xprv[a-zA-Z0-9]{107}$|xpub[a-zA-Z0-9]{107}$"),
    "Zcash Transparent Address": re.compile(r"t1[a-zA-Z0-9]{33}$"),
    "Tezos Public Key": re.compile(r"tz[1-9A-HJ-NP-Za-km-z]{34}$"),
    "Cardano Extended Public Key": re.compile(r"xpub[a-zA-Z0-9]{182}$"),
    "Stellar Account ID": re.compile(r"G[a-zA-Z0-9]{54}$"),
    "NEO Wallet Address": re.compile(r"A[a-zA-Z0-9]{33}$"),
    "IOTA Address": re.compile(r"[A-Z9]{90}"),
    "Ripple Address": re.compile(r"r[a-zA-Z0-9]{33}$"),
    "SSH Private Key (DSA)": re.compile(r"-----BEGIN DSA PRIVATE KEY-----[a-zA-Z0-9/+=]+-----END DSA PRIVATE KEY-----"),
    "SSH Private Key (ECDSA)": re.compile(r"-----BEGIN EC PRIVATE KEY-----[a-zA-Z0-9/+=]+-----END EC PRIVATE KEY-----"),
    "SSH Private Key (Ed25519)": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9/+=]+-----END OPENSSH PRIVATE KEY-----"),
    "BitLocker Recovery Key": re.compile(r"[0-9BCDFGHJKMPQRTVWXY]{6}-[0-9BCDFGHJKMPQRTVWXY]{6}-[0-9BCDFGHJKMPQRTVWXY]{6}-[0-9BCDFGHJKMPQRTVWXY]{6}-[0-9BCDFGHJKMPQRTVWXY]{6}"),
    "VeraCrypt Recovery Key": re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}"),
    "TrueCrypt Volume Keyfile": re.compile(r"[0-9A-Fa-f]{64}\.keyfile"),
    "GPG Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[a-zA-Z0-9/+=]+-----END PGP PRIVATE KEY BLOCK-----"),
    "Android Keystore Key": re.compile(r"-----BEGIN (?:.*\n)*.*ENCRYPTED PRIVATE KEY(?:.*\n)+.*-----END (?:.*\n)*"),
    "Windows Credential Manager Entry": re.compile(r"\[.*\]\nUsername=.*\nPassword=.*\n"),
    "KeePass Database Master Key": re.compile(r"Database Master Key: .*"),
    "Slack Token": re.compile(r"(?i)slack.*['|\"]xox[baprs]-\w{12}-\w{12}-\w{12}['|\"]"),
    "Git Token": re.compile(r"(?i)git.*['|\"]\w{40}['|\"]"),
    "Tinder API Token": re.compile(r"(?i)tinder.*['|\"]\w{32}['|\"]"),
    "Jenkins API Token": re.compile(r"(?i)jenkins.*['|\"]\w{32}['|\"]"),
    "PagerDuty Integration Key": re.compile(r"(?i)pdintegration.*['|\"]\w{32}['|\"]"),
    "Docker Hub Token": re.compile(r"(?i)dockerhub.*['|\"]\w{32}['|\"]"),
    "JFrog Artifactory API Key": re.compile(r"(?i)artifactory.*['|\"]\w{40}['|\"]"),
    "Kubernetes Config File": re.compile(r"(?i)apiVersion: v1.*kind: Config"),
    "Hashicorp Consul Token": re.compile(r"(?i)consul.*['|\"]\w{16}['|\"]"),
    "Datadog API Key": re.compile(r"(?i)datadog.*['|\"]\w{32}['|\"]"),
    "Dynatrace API Token": re.compile(r"(?i)dynatrace.*['|\"]\w{32}['|\"]"),
    "New Relic API Key": re.compile(r"(?i)newrelic.*['|\"]\w{40}['|\"]"),
    "Splunk HEC Token": re.compile(r"(?i)splunk.*token\s*:\s*['|\"]\w{32}['|\"]"),
    "Puppet Forge API Token": re.compile(r"(?i)puppet.*['|\"]\w{64}['|\"]"),
    "Azure Service Principal Client Secret": re.compile(r"(?i)azure.*client\s*secret\s*=\s*['|\"]\w{44}['|\"]"),
    "Azure Storage Account Key": re.compile(r"(?i)azure.*storageaccountkey\s*=\s*['|\"]\w{88}==['|\"]"),
    "Azure Cosmos DB Primary Key": re.compile(r"(?i)azure.*primary\s*key\s*=\s*['|\"]\w{64}['|\"]"),
    "Azure SAS Token": re.compile(r"(?i)azure.*sas\s*=\s*['|\"]\w{32}['|\"]"),
    "AWS S3 Access Key": re.compile(r"(?i)aws.*s3.*access\s*key\s*=\s*['|\"]\w{20}['|\"]"),
    "AWS S3 Secret Key": re.compile(r"(?i)aws.*s3.*secret\s*key\s*=\s*['|\"]\w{40}['|\"]"),
    "AWS Lambda Function Key": re.compile(r"(?i)aws.*lambda.*function.*key\s*=\s*['|\"]\w{30}['|\"]"),
    "IBM Cloud API Key": re.compile(r"(?i)ibm.*api.*key\s*:\s*['|\"]\w{44}['|\"]"),
    "IBM Cloud IAM API Key": re.compile(r"(?i)ibm.*iam.*api.*key\s*:\s*['|\"]\w{44}['|\"]"),
    "Jupyter Notebook Token": re.compile(r"(?i)jupyter.*token\s*=\s*['|\"]\w{32}['|\"]"),
    "AWS Elastic Beanstalk API Key": re.compile(r"(?i)aws.*elasticbeanstalk.*api.*key\s*=\s*['|\"]\w{20}['|\"]"),
    "Google Cloud Service Account Key": re.compile(r"(?i)google.*service.*account.*key\s*:\s*['|\"]\w{88}['|\"]"),
    "Google Cloud Firestore API Key": re.compile(r"(?i)google.*firestore.*api.*key\s*=\s*['|\"]\w{40}['|\"]"),
    "Google Cloud Storage API Key": re.compile(r"(?i)google.*storage.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Speech API Key": re.compile(r"(?i)google.*speech.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Vision API Key": re.compile(r"(?i)google.*vision.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Translation API Key": re.compile(r"(?i)google.*translation.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Natural Language API Key": re.compile(r"(?i)google.*language.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Video Intelligence API Key": re.compile(r"(?i)google.*video.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Datastore API Key": re.compile(r"(?i)google.*datastore.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud BigQuery API Key": re.compile(r"(?i)google.*bigquery.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Dataproc API Key": re.compile(r"(?i)google.*dataproc.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Pub/Sub API Key": re.compile(r"(?i)google.*pubsub.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Spanner API Key": re.compile(r"(?i)google.*spanner.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Compute Engine API Key": re.compile(r"(?i)google.*compute.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Dialogflow API Key": re.compile(r"(?i)google.*dialogflow.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Realtime Database API Key": re.compile(r"(?i)google.*firebase.*realtime.*database.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Cloud Messaging (FCM) API Key": re.compile(r"(?i)google.*firebase.*cloud.*messaging.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Authentication API Key": re.compile(r"(?i)google.*firebase.*authentication.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Hosting API Key": re.compile(r"(?i)google.*firebase.*hosting.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Test Lab API Key": re.compile(r"(?i)google.*firebase.*test.*lab.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Remote Config API Key": re.compile(r"(?i)google.*firebase.*remote.*config.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase In-App Messaging API Key": re.compile(r"(?i)google.*firebase.*in.*app.*messaging.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
    "Google Cloud Firebase Dynamic Links API Key": re.compile(r"(?i)google.*firebase.*dynamic.*links.*api.*key\s*=\s*['|\"]\w{39}['|\"]"),
}
        }
        self.discord_webhook_url = discord_webhook_url
        self.results: Set[ScanResult] = set()  # Use a set to avoid duplicates
        self.visited_urls: Set[str] = set()
        self.session: Optional[ClientSession] = None
        self.sem: Optional[asyncio.Semaphore] = None
        self.urls_with_params: Set[str] = set()  # Store unique URLs with parameters
        self.setup_logging()

    def setup_logging(self):
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    async def send_discord_notification(self, message: str):
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"content": message}
                await session.post(self.discord_webhook_url, json=payload)
        except Exception as e:
            self.logger.error(f"Error sending Discord notification: {e}")

    async def fetch(self, url: str, retry_count: int = 0) -> Optional[str]:
        async with self.sem:
            try:
                async with self.session.get(url, ssl=False) as response:
                    if response.status == 200:
                        data = await response.read()
                        encoding = response.charset or 'utf-8'
                        return data.decode(encoding, errors='replace')

                    # Handle common HTTP errors gracefully
                    if response.status in [401, 502, 503, 404, 400, 500, 204]:
                        return None

                    self.logger.warning(f"Status {response.status} for {url}")
                    return None

            except asyncio.TimeoutError:
                self.logger.error(f"Timeout occurred while fetching {url}. Retrying...")
                if retry_count < self.config["retry_limit"]:
                    await asyncio.sleep(2 * (retry_count + 1))  # Exponential backoff
                    return await self.fetch(url, retry_count + 1)
                return None

            except Exception as e:
                self.logger.error(f"Error fetching {url}: {str(e)}")
                if retry_count < self.config["retry_limit"]:
                    await asyncio.sleep(2 * (retry_count + 1))  # Exponential backoff
                    return await self.fetch(url, retry_count + 1)
                return None

    async def scan_js_content(self, content: str, context: str, is_inline: bool = False) -> List[ScanMatch]:
        matches = []
        lines = content.splitlines()

        for key, pattern in self.config["patterns"].items():
            for i, line in enumerate(lines):
                for match in pattern.finditer(line):
                    snippet = match.group(0).strip()
                    column_number = line.find(snippet) + 1
                    matches.append(ScanMatch(key, snippet, f"{context} (Line {i + 1}, Column {column_number})"))

                    location_info = f"Found '{key}' pattern in {context}:\n`{snippet}` (Line {i + 1}, Column {column_number})"
                    await self.send_discord_notification(location_info)
        return matches

    async def process_js_file(self, js_url: str) -> List[ScanMatch]:
        content = await self.fetch(js_url)
        if not content:
            return []

        # Check if the content is Base64-encoded JavaScript
        if content.startswith("data:application/x-javascript;base64,"):
            try:
                encoded_data = content.split(",", 1)[1]
                content = base64.b64decode(encoded_data).decode("utf-8", errors='replace')
            except Exception as e:
                # Log the error and skip this particular URL if decoding fails
                self.logger.error(f"Base64 decode error for {js_url}: {e}")
                return []  # Return empty list to skip the faulty JavaScript content

        # Continue to scan the JavaScript content
        return await self.scan_js_content(content, f"External JS: {js_url}")

    def parse_html_or_xml(self, content: str) -> BeautifulSoup:
        try:
            if content.strip().startswith("<?xml"):
                return BeautifulSoup(content, "xml")
            else:
                return BeautifulSoup(content, "lxml")
        except Exception as e:
            self.logger.error(f"Error parsing content: {e}")
            return BeautifulSoup(content, "html.parser")

    async def crawl_page(self, url: str, base_url: str, depth: int, progress: Progress, task_id: int):
        if depth > self.config["depth"] or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        progress.update(task_id, description=f"Scanning: {url}", completed=progress.tasks[task_id].completed + 1)

        content = await self.fetch(url)
        if not content:
            return

        soup = self.parse_html_or_xml(content)

        js_urls = [urljoin(url, script["src"]) for script in soup.find_all("script", src=True)]
        for js_url in js_urls:
            matches = await self.process_js_file(js_url)
            if matches:
                self.results.add(ScanResult(url, js_url, tuple(matches)))  # Convert list to tuple to ensure uniqueness

        for idx, script in enumerate(soup.find_all("script", src=False)):
            matches = await self.scan_js_content(
                script.get_text(),
                f"Inline Script #{idx + 1}",
                is_inline=True
            )
            if matches:
                self.results.add(ScanResult(url, f"{url}#inline-{idx}", tuple(matches)))  # Convert list to tuple to ensure uniqueness

        # Extract URLs with parameters and save them
        self.extract_and_save_urls_with_params(soup)

        if depth < self.config["depth"]:
            next_urls = [
                urljoin(url, a["href"]) 
                for a in soup.find_all("a", href=True)
                if self.is_valid_url(urljoin(url, a["href"]))
                and urlparse(base_url).netloc == urlparse(urljoin(url, a["href"])).netloc
            ]
            
            tasks = [self.crawl_page(next_url, base_url, depth + 1, progress, task_id) 
                    for next_url in next_urls]
            await asyncio.gather(*tasks)

    def is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and parsed.scheme in {"http", "https"}
        except Exception:
            return False

    def extract_and_save_urls_with_params(self, soup: BeautifulSoup):
        for anchor in soup.find_all("a", href=True):
            url = urljoin(anchor["href"], anchor["href"])
            if '?' in url:
                self.urls_with_params.add(url)

        # Save unique URLs with parameters to a text file
        if self.urls_with_params:
            output_file = Path(self.config["output_dir"]) / "urls_with_parameters.txt"
            with open(output_file, "w", encoding="utf-8") as f:
                for url in self.urls_with_params:
                    f.write(url + "\n")

    async def scan_websites(self, websites: List[str]):
        self.sem = asyncio.Semaphore(self.config["concurrency"])
        connector = TCPConnector(limit=self.config["concurrency"], ssl=False)
        timeout = ClientTimeout(total=self.config["timeout"])
        
        headers = {"User-Agent": self.config["user_agent"]}
        
        async with ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            self.session = session
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                main_task_id = progress.add_task("Scanning websites...", total=len(websites))
                
                for website in websites:
                    await self.crawl_page(website, website, 1, progress, main_task_id)
                    progress.advance(main_task_id)

    def save_results(self, output_format: str = "both"):
        # Create directory if not exists and handle results
        output_dir = Path(self.config["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        current_dir = Path(os.getcwd())  # Get the current directory where the script is running

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format in ("json", "both"):
            json_file = output_dir / f"scan_results_{timestamp}.json"
            json_data = [
                {
                    "website_url": result.website_url,
                    "js_url": result.js_url,
                    "matches": [
                        {
                            "key": match.key,
                            "snippet": match.snippet,
                            "context": match.context
                        }
                        for match in result.matches
                    ],
                    "timestamp": result.timestamp.isoformat()
                }
                for result in self.results
            ]
            
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2)

            current_json_file = current_dir / f"scan_results_{timestamp}.json"
            with open(current_json_file, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2)

        if output_format in ("txt", "both"):
            txt_file = output_dir / f"scan_results_{timestamp}.txt"
            with open(txt_file, "w", encoding="utf-8") as f:
                for result in self.results:
                    f.write(f"\nWebsite: {result.website_url}\n")
                    f.write(f"JavaScript Source: {result.js_url}\n")
                    f.write("Matches:\n")
                    for match in result.matches:
                        f.write(f"  - Type: {match.key}\n")
                        f.write(f"    Snippet: {match.snippet}\n")
                        f.write(f"    Context: {match.context}\n")
                    f.write("-" * 80 + "\n")

            current_txt_file = current_dir / f"scan_results_{timestamp}.txt"
            with open(current_txt_file, "w", encoding="utf-8") as f:
                for result in self.results:
                    f.write(f"\nWebsite: {result.website_url}\n")
                    f.write(f"JavaScript Source: {result.js_url}\n")
                    f.write("Matches:\n")
                    for match in result.matches:
                        f.write(f"  - Type: {match.key}\n")
                        f.write(f"    Snippet: {match.snippet}\n")
                        f.write(f"    Context: {match.context}\n")
                    f.write("-" * 80 + "\n")

        return output_dir


# Input and user interaction
def validate_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def get_user_input() -> Tuple[List[str], str, int, int]:
    console.print(Panel.fit(
        "[bold blue]Dons JS Scanner[/bold blue]\n"
        "A tool for scanning websites and their JavaScript files for sensitive information.",
        title="Welcome",
        border_style="blue"
    ))

    discord_webhook_url = Prompt.ask("Enter your Discord Webhook URL")
    depth = int(Prompt.ask("Enter the crawl depth", default="4"))
    concurrency = int(Prompt.ask("Enter the concurrency level", default="50"))
    timeout = int(Prompt.ask("Enter the timeout (in seconds)", default="30"))

    while True:
        choice = Prompt.ask(
            "How would you like to input websites?",
            choices=["file", "single", "multiple"],
            default="single"
        )

        websites = []
        if choice == "file":
            while True:
                file_path = Prompt.ask("Enter the path to the file containing website URLs")
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        websites = [line.strip() for line in f if validate_url(line.strip())]
                    if websites:
                        break
                    console.print("[red]No valid URLs found in the file.[/red]")
                except FileNotFoundError:
                    console.print("[red]File not found. Please check the path.[/red]")
                except Exception as e:
                    console.print(f"[red]Error reading file: {e}[/red]")
        
        elif choice == "single":
            while True:
                url = Prompt.ask("Enter the website URL (including http:// or https://)")
                if validate_url(url):
                    websites = [url]
                    break
                console.print("[red]Invalid URL format. Please include http:// or https://[/red]")
        
        else:  # multiple
            console.print("Enter URLs one per line (press Enter twice when done):")
            while True:
                url = input()
                if not url:
                    break
                if validate_url(url):
                    websites.append(url)
                else:
                    console.print(f"[yellow]Skipping invalid URL: {url}[/yellow]")

        if websites:
            break
        console.print("[red]No valid URLs provided. Please try again.[/red]")

    output_format = Prompt.ask(
        "Choose output format",
        choices=["txt", "json", "both"],
        default="both"
    )

    return websites, discord_webhook_url, depth, concurrency, timeout

async def main():
    try:
        websites, discord_webhook_url, depth, concurrency, timeout = get_user_input()

        with Status("[bold blue]Initializing scanner...[/bold blue]"):
            scanner = WebsiteScanner(discord_webhook_url, depth, concurrency, timeout)

        console.print(f"\n[bold green]Starting scan of {len(websites)} website(s)[/bold green]")
        console.print("Configuration:", style="blue")
        console.print(f"  Depth: {depth}")
        console.print(f"  Concurrency: {concurrency}")
        console.print(f"  Timeout: {timeout} seconds")
        console.print()

        start_time = datetime.now()
        await scanner.scan_websites(websites)
        duration = datetime.now() - start_time

        output_dir = scanner.save_results("both")

        # Display summary
        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print(f"Duration: {duration.total_seconds():.2f} seconds")
        console.print(f"Websites scanned: {len(websites)}")
        console.print(f"URLs visited: {len(scanner.visited_urls)}")
        console.print(f"Matches found: {len(scanner.results)}")
        console.print(f"\nResults saved to: {output_dir}")

        if scanner.results:
            if Confirm.ask("Would you like to see a summary of the findings?"):
                table = Table(title="Scan Results Summary")
                table.add_column("Website", style="cyan")
                table.add_column("Source", style="blue")
                table.add_column("Matches", style="red")

                for result in scanner.results:
                    table.add_row(
                        result.website_url,
                        result.js_url,
                        str(len(result.matches))
                    )

                console.print(table)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan aborted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]An error occurred: {str(e)}[/red]")
        logging.exception("Unexpected error during scan")
    finally:
        if Confirm.ask("Press Enter to exit"):
            pass

if __name__ == "__main__":
    asyncio.run(main())
