import os
import re
import asyncio
import logging
import base64
import json
import csv
from pathlib import Path
from urllib.parse import urljoin, urlparse
from datetime import datetime, timezone

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import jsbeautifier
from rich.console import Console
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich import box
import ssl
import warnings
from typing import List, Tuple

from logging.handlers import RotatingFileHandler

# Suppress specific BeautifulSoup warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Initialize Rich console
console = Console(style="green", width=120, height=30)

# Configure logging with rotating file handler
logger = logging.getLogger("WebsiteScanner")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("website_scanner.log", maxBytes=5 * 1024 * 1024, backupCount=2)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Precompile regex patterns for performance
regex_patterns = {
    # Existing and new patterns (flattened)
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
    "Authorization Bearer Token": re.compile(r"bearer [a-zA-Z0-9_\-\.=]+", re.IGNORECASE),
    "JWT Token": re.compile(r"ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*$", re.IGNORECASE),
    "Facebook Access Token": re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
    "Facebook App ID": re.compile(r"(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}"),
    "Google Cloud Platform API Key": re.compile(r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Google Cloud Platform OAuth Token": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "Windows Live API Key": re.compile(r"(?i)windowslive.*['|\"][0-9a-f]{22}['|\"]"),
    "Bitcoin Private Key (WIF)": re.compile(r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$"),
    "Ethereum Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Ripple Secret Key": re.compile(r"s[a-zA-Z0-9]{53}$"),
    "Litecoin Private Key (WIF)": re.compile(r"[LK][1-9A-HJ-NP-Za-km-z]{50}$"),
    "Bitcoin Cash Private Key (WIF)": re.compile(r"[Kk][1-9A-HJ-NP-Za-km-z]{50,51}$"),
    "Cardano Extended Private Key": re.compile(r"xprv[a-zA-Z0-9]{182}$"),
    "Monero Private Spend Key": re.compile(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"),
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
    "JIRA API Token": re.compile(r"(?i)jira.*['|\"]\w{16}['|\"]"),
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

class WebsiteScanner:
    DEFAULT_DEPTH = 4
    DEFAULT_CONCURRENCY = 50
    RETRY_LIMIT = 3
    MAX_URLS = 1000  # Maximum number of URLs to scan to prevent infinite loops

    def __init__(self, depth: int = None, concurrency: int = None, output_format: str = "txt", discord_webhook: str = None):
        self.depth = depth or self.DEFAULT_DEPTH
        self.concurrency = concurrency or self.DEFAULT_CONCURRENCY
        self.output_format = output_format.lower()
        self.discord_webhook = discord_webhook
        self.matches_file_path = Path.home() / "Desktop" / f"matches.{self.output_format}"
        self.sem = asyncio.Semaphore(self.concurrency)
        self.session = None
        self.results = set()
        self.visited_urls = set()
        self.js_files_scanned = set()
        self.url_count = 0  # To track the number of URLs scanned
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')  # Lower security level for compatibility; adjust as needed
        logger.info(f"Initialized WebsiteScanner with depth={self.depth}, concurrency={self.concurrency}, output_format={self.output_format}")

    @staticmethod
    def get_user_input() -> Tuple[List[str], int, int, str, str]:
        header = r"""
    ######################################################################
    #    ____                      _____                                 #
    #   / __ \____  ____  _____   / ___/_________ _____  ____  ___  _____#
    #  / / / / __ \/ __ \/ ___/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/#
    # / /_/ / /_/ / / / (__  )   ___/ / /__/ /_/ / / / / / / /  __/ /    #
    #/_____/\____/_/ /_/____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     #
    ######################################################################
                                                           #By Ali Essam


        """
        console.print(Panel(header, style="bold green", border_style="cyan"))
        console.print(Panel("[bold red]Please use this tool responsibly and ensure you have permission to scan the target websites.[/bold red]", border_style="yellow"))

        # Prompt for Discord webhook URL
        while True:
            discord_webhook = Prompt.ask("Enter your Discord Webhook URL (or leave blank to skip)", default="", show_default=False).strip()
            if discord_webhook and not discord_webhook.startswith("https://discord.com/api/webhooks/"):
                console.print("[bold red]Invalid Discord Webhook URL. Please enter a valid URL or leave blank to skip.[/bold red]")
            else:
                break

        # Choose scan type
        scan_type = Prompt.ask("Scan multiple websites from a file or a single website?", choices=["file", "single"], default="single")
        websites = []

        if scan_type == "file":
            while True:
                file_path = Prompt.ask("Enter the path to the file containing website URLs")
                if Path(file_path).is_file():
                    with open(file_path, "r", encoding="utf-8") as f:
                        websites = [line.strip() for line in f if line.strip()]
                    if not websites:
                        console.print("[bold red]The file is empty. Please provide a file with valid URLs.[/bold red]")
                        continue
                    break
                else:
                    console.print("[bold red]File not found. Please enter a valid file path.[/bold red]")
        else:
            while True:
                website = Prompt.ask("Enter the website URL (type 'done' to finish)", default="", show_default=False).strip()
                if website.lower() == 'done':
                    break
                if website.startswith(("http://", "https://")) and urlparse(website).netloc:
                    websites.append(website)
                else:
                    console.print("[bold red]Invalid URL. Please include http:// or https:// and ensure it's properly formatted.[/bold red]")
            if not websites:
                console.print("[bold red]No websites entered. Exiting.[/bold red]")
                exit()

        # Input validation for depth
        while True:
            depth_input = Prompt.ask(
                f"Enter the recursive depth for scanning (default is {WebsiteScanner.DEFAULT_DEPTH})",
                default=str(WebsiteScanner.DEFAULT_DEPTH)
            )
            try:
                depth = int(depth_input)
                if depth < 1:
                    console.print("[bold red]Depth must be at least 1.[/bold red]")
                    continue
                break
            except ValueError:
                console.print("[bold red]Please enter a valid integer for depth.[/bold red]")

        # Input validation for concurrency
        while True:
            concurrency_input = Prompt.ask(
                f"Enter the number of concurrent connections (default is {WebsiteScanner.DEFAULT_CONCURRENCY})",
                default=str(WebsiteScanner.DEFAULT_CONCURRENCY)
            )
            try:
                concurrency = int(concurrency_input)
                if concurrency < 10 or concurrency > 1000:
                    console.print("[bold red]Concurrency must be between 10 and 1000.[/bold red]")
                    continue
                break
            except ValueError:
                console.print("[bold red]Please enter a valid integer for concurrency.[/bold red]")

        # Choose output format
        output_format = Prompt.ask(
            "Choose output format",
            choices=["txt", "json", "csv"],
            default="txt"
        )

        return websites, depth, concurrency, output_format, discord_webhook

    async def fetch(self, url: str, retry_count: int = 0) -> Tuple[str, str]:
        async with self.sem:
            try:
                async with self.session.get(url, ssl=self.ssl_context) as response:
                    if response.status == 200:
                        data = await response.read()
                        encoding = response.charset or 'utf-8'
                        text = data.decode(encoding, errors='replace')
                        content_type = response.headers.get('Content-Type', '').lower()
                        return text, content_type
                    else:
                        logger.warning(f"Non-200 status code {response.status} for URL: {url}")
            except asyncio.TimeoutError:
                logger.error(f"Timeout error fetching URL {url}")
            except Exception as e:
                logger.error(f"Error fetching URL {url}: {e}")

            if retry_count < self.RETRY_LIMIT:
                logger.info(f"Retrying ({retry_count + 1}/{self.RETRY_LIMIT}) for URL: {url}")
                return await self.fetch(url, retry_count + 1)
            else:
                logger.error(f"Failed to fetch URL after {self.RETRY_LIMIT} retries: {url}")
                return "", ""

    async def crawl_and_scan(self, url: str, base_url: str, current_depth: int, progress_task):
        if current_depth > self.depth:
            return
        parsed_base = urlparse(base_url)
        parsed_url = urlparse(url)
        if parsed_base.netloc != parsed_url.netloc:
            return
        if url in self.visited_urls:
            return
        if self.url_count >= self.MAX_URLS:
            logger.info(f"Reached maximum URL limit of {self.MAX_URLS}. Stopping scan.")
            return

        self.visited_urls.add(url)
        self.url_count += 1
        logger.debug(f"Crawling URL: {url} at depth {current_depth}")

        html_content, content_type = await self.fetch(url)
        if not html_content:
            return

        parser = 'xml' if 'xml' in content_type else 'lxml'

        try:
            soup = BeautifulSoup(html_content, parser)
        except Exception as e:
            logger.error(f"Error parsing {url} with parser {parser}: {e}")
            return

        # Extract and process external JS files
        js_urls = [urljoin(url, script.get("src")) for script in soup.find_all("script", src=True)]
        js_urls = [js_url for js_url in js_urls if self.is_valid_url(js_url)]
        tasks = [self.scan_js_file(js_url, progress_task) for js_url in js_urls if js_url not in self.js_files_scanned]

        # Extract and scan inline scripts
        inline_scripts = [script.string for script in soup.find_all("script") if not script.get("src") and script.string]
        tasks.extend([self.scan_inline_js(script_content, url, progress_task) for script_content in inline_scripts])

        # Extract and scan JavaScript from event handlers
        event_handlers = ['onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout', 'onkeyup', 'onkeydown']
        inline_js_from_events = []
        for handler in event_handlers:
            elements = soup.find_all(attrs={handler: True})
            for elem in elements:
                js_code = elem.get(handler)
                if js_code:
                    inline_js_from_events.append(js_code)
        tasks.extend([self.scan_inline_js(js_code, url, progress_task) for js_code in inline_js_from_events])

        # Process JS scanning tasks in chunks
        chunk_size = 100  # Adjust based on performance needs
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            try:
                js_results = await asyncio.gather(*chunk, return_exceptions=True)
            except Exception as e:
                logger.error(f"Error during JS scanning tasks: {e}")
                continue

            for result in js_results:
                if isinstance(result, Exception):
                    logger.error(f"Error during JS scanning: {result}")
                    continue
                # Result is already processed in scan_js_file and scan_inline_js
                progress_task.update(total=self.url_count)  # Update total dynamically

        # Extract and enqueue next URLs
        next_urls = [urljoin(url, link.get("href")) for link in soup.find_all("a", href=True)]
        next_urls = [u for u in next_urls if self.is_valid_url(u) and self.is_same_domain(base_url, u)]
        allowed_extensions = ['', '.html', '.htm', '.php', '.asp', '.aspx', '.jsp']
        next_urls = [u for u in next_urls if os.path.splitext(urlparse(u).path)[1].lower() in allowed_extensions]

        # Recursively crawl next URLs
        tasks = [self.crawl_and_scan(u, base_url, current_depth + 1, progress_task) for u in next_urls]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def scan_js_file(self, js_url: str, progress_task) -> Tuple[str, List[Tuple[str, str]]]:
        logger.debug(f"Scanning JS file: {js_url}")
        js_content, _ = await self.fetch(js_url)
        if not js_content:
            return js_url, []

        self.js_files_scanned.add(js_url)
        js_content = self.beautify_js(js_content)

        # Decode base64 encoded JS if applicable
        if js_content.startswith("data:application/x-javascript;base64,"):
            try:
                js_content = base64.b64decode(js_content.split(",")[1]).decode("utf-8", errors='replace')
            except Exception as e:
                logger.error(f"Failed to decode base64 JS content from {js_url}: {e}")
                return js_url, []

        matches = self.search_patterns(js_content)
        confirmed_matches = self.confirm_matches(matches)
        if confirmed_matches:
            await self.save_and_display_matches(js_url, matches)
        progress_task.advance()

        return js_url, confirmed_matches

    async def scan_inline_js(self, js_content: str, page_url: str, progress_task) -> Tuple[str, List[Tuple[str, str]]]:
        logger.debug(f"Scanning inline JS in {page_url}")
        js_content = self.beautify_js(js_content)
        matches = self.search_patterns(js_content)
        confirmed_matches = self.confirm_matches(matches)
        if confirmed_matches:
            await self.save_and_display_matches(page_url, matches)
        progress_task.advance()

        return f"Inline script in {page_url}", confirmed_matches

    def beautify_js(self, js_content: str) -> str:
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            beautified_js = jsbeautifier.beautify(js_content, opts)
            return beautified_js
        except Exception as e:
            logger.warning(f"Failed to beautify JS content: {e}")
            return js_content

    def search_patterns(self, js_content: str) -> List[Tuple[str, str]]:
        matches = []
        for key, pattern in regex_patterns.items():
            for match in pattern.finditer(js_content):
                snippet = match.group(0).strip()
                matches.append((key, snippet))
        return matches

    def confirm_matches(self, matches: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        # Instead of fullmatch, we check if the pattern is found anywhere in the snippet
        confirmed = []
        for key, snippet in matches:
            if key in regex_patterns and regex_patterns[key].search(snippet):
                confirmed.append((key, snippet))
        return confirmed

    async def send_discord_notification(self, key: str, snippet: str, source: str):
        if not self.discord_webhook:
            return
        embed = {
            "title": f"🔍 New Finding: {key}",
            "description": f"**Snippet:** ```{snippet}```\n**Source:** {source}",
            "color": 0xFF0000,
            "fields": [
                {
                    "name": "Key",
                    "value": key,
                    "inline": True
                },
                {
                    "name": "Snippet",
                    "value": f"```{snippet}```",
                    "inline": False
                },
                {
                    "name": "Source URL",
                    "value": source,
                    "inline": False
                }
            ],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        data = {"embeds": [embed]}
        try:
            async with self.session.post(self.discord_webhook, json=data) as response:
                if response.status in [200, 204]:
                    logger.info(f"Successfully sent Discord notification for {key}")
                else:
                    logger.error(f"Failed to send Discord notification for {key}: HTTP {response.status}")
        except Exception as e:
            logger.error(f"Error sending Discord notification: {e}")

    async def save_and_display_matches(self, source: str, matches: List[Tuple[str, str]]):
        if not matches:
            return

        # Save to file
        if self.output_format == "json":
            match_data = {
                "source": source,
                "matches": [{"key": key, "snippet": snippet} for key, snippet in matches]
            }
            with open(self.matches_file_path, "a", encoding="utf-8") as file:
                json.dump(match_data, file, indent=2)
                file.write(",\n")
        elif self.output_format == "csv":
            with open(self.matches_file_path, "a", newline='', encoding="utf-8") as file:
                writer = csv.writer(file)
                for key, snippet in matches:
                    writer.writerow([source, key, snippet])
        else:
            with open(self.matches_file_path, "a", encoding="utf-8") as file:
                file.write(f"\nMatches found at {source}:\n")
                for key, snippet in matches:
                    file.write(f"  [{key}]\n    Snippet: {snippet}\n")

        # Display in console using Rich with detailed formatting
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Key", style="cyan", no_wrap=True)
        table.add_column("Snippet", style="yellow")
        table.add_column("Source", style="green")

        for key, snippet in matches:
            table.add_row(key, snippet, source)
            # Send Discord notification
            asyncio.create_task(self.send_discord_notification(key, snippet, source))

        console.print(Panel(table, title=f"🔍 Matches in {source}", title_align="left", border_style="green"))

    async def scan_websites(self, websites: List[str]):
        connector = TCPConnector(limit=self.concurrency, ssl=self.ssl_context)
        timeout = ClientTimeout(total=30)
        headers = {"User-Agent": "WebsiteScanner/3.0 (+https://github.com/yourusername/website-scanner)"}
        async with ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            self.session = session
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold green]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True
            ) as progress:
                scan_task = progress.add_task("Scanning websites...", total=self.MAX_URLS)
                tasks = [self.crawl_and_scan(website, website, 1, scan_task) for website in websites]
                await asyncio.gather(*tasks, return_exceptions=True)
                progress.update(scan_task, completed=self.url_count)
        logger.info("Scanning completed.")
        self.display_summary()

    def display_summary(self):
        total_matches = len(self.results)
        if total_matches:
            summary_table = Table(title="Scan Summary", box=box.ROUNDED, header_style="bold magenta")
            summary_table.add_column("Total Matches", justify="right", style="bold red")
            summary_table.add_column("Output File", style="green")
            summary_table.add_row(str(total_matches), str(self.matches_file_path))
            console.print(Panel(summary_table, title="Summary", border_style="blue"))
            console.print(f"[bold green]Scan completed successfully. Results saved to {self.matches_file_path}[/bold green]")
        else:
            console.print(Panel("[bold green]No matches found.[/bold green]", title="Summary", border_style="blue"))
            console.print(f"[bold green]Scan completed successfully. No matches were found.[/bold green]")
        console.print("[bold blue]Press Enter to exit.[/bold blue]")
        input()

    def is_valid_url(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc

    def is_same_domain(self, base_url: str, target_url: str) -> bool:
        return urlparse(base_url).netloc == urlparse(target_url).netloc

def main():
    try:
        websites, depth, concurrency, output_format, discord_webhook = WebsiteScanner.get_user_input()
        console.print(f"\n[bold cyan]Scanning {len(websites)} website(s) with recursive depth of {depth} and concurrency of {concurrency}...\n[/bold cyan]")
        scanner = WebsiteScanner(depth=depth, concurrency=concurrency, output_format=output_format, discord_webhook=discord_webhook)
        asyncio.run(scanner.scan_websites(websites))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan aborted by the user.[/bold yellow]")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
    finally:
        console.print("[bold blue]Press Enter to exit.[/bold blue]")
        try:
            input()
        except EOFError:
            pass

if __name__ == "__main__":
    main()
