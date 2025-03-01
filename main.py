#!/usr/bin/env python3
"""
Advanced TreasureScanner v5.0.0
Last Updated: {LAST_UPDATED}

A next-gen JavaScript vulnerability scanner for bug bounty workflows.
Features:
 • Ultra-fast asynchronous scanning with aiohttp using an async queue and worker tasks.
 • Multiple input methods: command‑line arguments, text file, or interactive input.
 • Rich, colorful UI/UX using Rich for banners, progress, and summaries.
 • Multi-format reporting: JSON, TXT, and HTML.
 • Integrated scanning for sensitive keys/tokens and S3 bucket URLs.
 • Robust logging using RotatingFileHandler.
"""

import os, re, asyncio, logging, math, json, base64
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any, Set
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector, ClientError
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from logging.handlers import RotatingFileHandler

from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TimeRemainingColumn
)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
import typer

# Disable insecure request warnings
urllib3.disable_warnings(InsecureRequestWarning)

# ------------------------- Global Variables & Theme Setup -------------------------
VERSION = "5.0.0"
LAST_UPDATED = datetime.now().strftime("%B %d, %Y")

custom_theme = Theme({
    "banner": "bold bright_blue",
    "header": "bold bright_blue",
    "subheader": "bold bright_cyan",
    "prompt": "bold bright_yellow",
    "success": "bold green",
    "warning": "bold red",
    "critical": "bold white on red",
    "info": "bright_cyan",
    "data": "bright_magenta",
    "url": "underline bright_green",
    "key": "bold bright_red",
    "value": "bright_yellow",
    "context": "dim white",
    "progress.bar.finished": "green",
    "progress.bar.pulse": "bright_blue",
})
console = Console(theme=custom_theme, style="white on black", highlight=True, emoji=True)

def display_banner() -> None:
    banner_text = Text.from_markup(
        "[banner]▄▄▄█████▓ ██▀███  ▓█████  ▄▄▄        ██████  █    ██  ██▀███  ▓█████[/banner]\n"
        "[banner]▓  ██▒ ▓▒▓██ ▒ ██▒▓█   ▀ ▒████▄    ▒██    ▒  ██  ▓██▒▓██ ▒ ██▒▓█   ▀[/banner]\n"
        "[banner]▒ ▓██░ ▒░▓██ ░▄█ ▒▒███   ▒██  ▀█▄  ░ ▓██▄   ▓██  ▒██░▓██ ░▄█ ▒▒███[/banner]\n"
        "[banner]░ ▓██▓ ░ ▒██▀▀█▄  ▒▓█  ▄ ░██▄▄▄▄██   ▒   ██▒▓▓█  ░██░▒██▀▀█▄  ▒▓█  ▄[/banner]\n"
        "[banner]  ▒██▒ ░ ░██▓ ▒██▒░▒████▒ ▓█   ▓██▒▒██████▒▒▒▒█████▓ ░██▓ ▒██▒░▒████▒[/banner]\n"
        "[banner]  ▒ ░░   ░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░[/banner]\n"
        "[banner]    ░      ░░   ░    ░  ░  ▒   ▒▒ ░░ ░▒  ░ ░░░▒░ ░ ░   ░░   ░    ░[/banner]\n"
        "[banner]  ░        ░        ░     ░   ▒   ░  ░  ░   ░░░ ░ ░        ░  ░[/banner]\n"
        "[banner]            ░        ░  ░      ░  ░      ░     ░        ░        ░  ░[/banner]\n"
        f"[info]Advanced TreasureScanner v{VERSION}[/info]\n"
        f"[data]Last Updated: {LAST_UPDATED}[/data]"
    )
    console.print(Panel(banner_text, border_style="bright_blue", padding=(1, 2)), justify="center")

def compute_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def is_valid_token(key: str, token: str) -> bool:
    # For S3 bucket URLs, use a lower length threshold.
    if key == "AWS S3 Bucket URL":
        return len(token) >= 5
    return len(token) >= 10 and compute_entropy(token) >= 4.5

# ------------------------- API Key Patterns (Bug Bounty Relevant) -------------------------
# These patterns include keys/tokens that are sensitive for bug bounty reporting.
api_key_patterns = {
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
    "Windows Live API Key": re.compile(r"(?i)windowslive.*['|\"][0-9a-f]{22}['|\"]"),
    "Bitcoin Private Key (WIF)": re.compile(r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$"),
    "Ethereum Private Key": re.compile(r"0x[a-fA-F0-9]{64}"),
    "Ripple Secret Key": re.compile(r"s[a-zA-Z0-9]{53}$"),
    "Litecoin Private Key (WIF)": re.compile(r"[LK][1-9A-HJ-NP-Za-km-z]{50}$"),
    "Bitcoin Cash Private Key (WIF)": re.compile(r"[Kk][1-9A-HJ-NP-Za-km-z]{50,51}$"),
    "Cardano Extended Private Key": re.compile(r"xprv[a-zA-Z0-9]{182}$"),
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
    "Azure Key Vault Secret Identifier": re.compile(r"https:\/\/[a-z0-9\-]+\.vault\.azure\.net\/secrets\/[a-zA-Z0-9\-]+\/[a-zA-Z0-9\-]+"),
    "Trello API Key": re.compile(r"(?i)trello.*['|\"]\w{32}['|\"]"),
    "Atlassian API Key": re.compile(r"(?i)atlassian.*['|\"]\w{32}['|\"]"),
    "Zendesk API Token": re.compile(r"(?i)zendesk.*['|\"]\w{40}['|\"]"),
    "Bitbucket OAuth Token": re.compile(r"(?i)bitbucket.*['|\"]\w{20,40}['|\"]"),
    "Discord OAuth Token": re.compile(r"(?i)discord.*['|\"]\w{59}['|\"]"),
    "NPM Token": re.compile(r"(?i)npm[_]?token.*['|\"]\w{64}['|\"]"),
    "CircleCI API Token": re.compile(r"(?i)circleci.*['|\"]\w{40}['|\"]"),
    "Hootsuite API Token": re.compile(r"(?i)hootsuite.*['|\"]\w{12}['|\"]"),
    "Twitch Client ID": re.compile(r"(?i)twitch(.{0,20})?['\"][0-9a-z]{30}['\"]"),
    "Twitch OAuth Token": re.compile(r"oauth:[a-z0-9]+", re.IGNORECASE),
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
    "Tinder API Token": re.compile(r"(?i)tinder.*['|\"]\w{32}['|\"]"),
    "Jenkins API Token": re.compile(r"(?i)jenkins.*['|\"]\w{32}['|\"]"),
    "PagerDuty Integration Key": re.compile(r"(?i)pdintegration.*['|\"]\w{32}['|\"]"),
    "Docker Hub Token": re.compile(r"(?i)dockerhub.*['|\"]\w{32}['|\"]"),
    "JFrog Artifactory API Key": re.compile(r"(?i)artifactory.*['|\"]\w{40}['|\"]"),
    "Kubernetes Config File": re.compile(r"(?i)apiVersion: v1.*kind: Config"),
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
	"AWS S3 Bucket URL": re.compile(r"https?://(?:[a-z0-9.-]+)\.s3(?:-website(?:-[a-z]+)?)?\.amazonaws\.com(?:/[^\s'\"<>]*)?"),

}

# ------------------------- Plugin System -------------------------
class ScannerPlugin:
    async def process(self, content: str, context: str, js_url: str) -> List[Dict[str, Any]]:
        return []

# ------------------------- Data Classes -------------------------
@dataclass(frozen=True)
class ScanMatch:
    key: str
    snippet: str
    context: str
    confidence: float
    line_number: Optional[int] = None
    column_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True)
class ScanResult:
    website_url: str
    location: str
    matches: Tuple[ScanMatch, ...]
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "website_url": self.website_url,
            "location": self.location,
            "matches": [m.to_dict() for m in self.matches],
            "timestamp": self.timestamp.isoformat()
        }

@dataclass
class WebsiteScanStats:
    websites_scanned: int = 0
    urls_visited: int = 0
    total_matches_found: int = 0
    scan_start_time: Optional[datetime] = None
    scan_end_time: Optional[datetime] = None

    @property
    def scan_duration(self) -> float:
        if self.scan_start_time and self.scan_end_time:
            return (self.scan_end_time - self.scan_start_time).total_seconds()
        return 0.0

    def start(self):
        self.scan_start_time = datetime.now()

    def end(self):
        self.scan_end_time = datetime.now()

# ------------------------- Helper: Scan Text for Secrets -------------------------
def scan_for_secrets(text: str, context: str) -> List[ScanMatch]:
    matches = []
    for key, pattern in api_key_patterns.items():
        for m in pattern.finditer(text):
            snippet = m.group(1) if m.lastindex else m.group(0)
            snippet = snippet.strip()
            # Use a lower threshold for S3 bucket URLs
            if not is_valid_token(key, snippet):
                continue
            entropy = compute_entropy(snippet)
            confidence = min(1.0, (len(snippet) / 50.0) + (entropy / 10.0))
            if confidence < 0.5:
                continue
            matches.append(ScanMatch(key, snippet, context, confidence))
    return matches

# ------------------------- Main Scanner Class -------------------------
class WebsiteScanner:
    def __init__(self, config: Dict[str, Any], plugins: Optional[List[ScannerPlugin]] = None):
        self.output_dir = Path(os.getcwd()) / "treasure_scanner_results"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.params_file = self.output_dir / f"urls_with_parameters_{timestamp}.txt"
        with open(self.params_file, "w", encoding="utf-8") as f:
            f.write("")
        self.params_lock = asyncio.Lock()

        user_agent = f"TreasureScanner/{VERSION} (Next-Gen Security Scanning)"
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        self.config = {
            "depth": config.get("depth", 4),
            "concurrency": config.get("concurrency", 50),
            "timeout": config.get("timeout", 30),
            "retry_limit": config.get("retry_limit", 3),
            "headers": headers,
            "verify_ssl": config.get("verify_ssl", True),
            "verbose": config.get("verbose", False)
        }
        self.discord_webhook_url = config.get("discord_webhook_url", "")
        self.send_discord = bool(self.discord_webhook_url)
        self.discord_max_per_file = config.get("discord_max_per_file", 5)
        self.results: Set[ScanResult] = set()
        self.visited_urls: Set[str] = set()
        self.session: Optional[ClientSession] = None
        self.sem: Optional[asyncio.Semaphore] = None
        self.urls_with_params: Dict[str, Dict[str, List[str]]] = {}
        self.discord_notifications_sent: Dict[str, Set[str]] = {}
        self.stats = WebsiteScanStats()
        self.media_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico'}
        self.domain_request_times: Dict[str, datetime] = {}
        self.domain_wait_time = 0.5
        self.plugins = plugins or []
        self.setup_logging()

    def setup_logging(self):
        try:
            log_dir = self.output_dir / "logs"
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
            handler.setFormatter(formatter)
            logging.basicConfig(level=logging.DEBUG, handlers=[handler])
            self.logger = logging.getLogger("AdvancedTreasureScanner")
            self.logger.info(f"Logging initialized. Log file: {log_file}")
        except Exception as e:
            console.print(f"[warning]Logging setup error: {e}[/warning]")
            logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
            self.logger = logging.getLogger("AdvancedTreasureScanner")

    async def send_discord_notification(self, js_url: str, message: str, severity: str = "info"):
        if not self.send_discord:
            return
        plain_message = re.sub(r"\[[^\]]+\]", "", message)
        if js_url not in self.discord_notifications_sent:
            self.discord_notifications_sent[js_url] = set()
        if plain_message in self.discord_notifications_sent[js_url]:
            return
        if len(self.discord_notifications_sent[js_url]) >= self.discord_max_per_file:
            return
        try:
            emoji_map = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️", "info": "🔍"}
            emoji = emoji_map.get(severity.lower(), "🔍")
            webhook_message = f"{emoji} TreasureScanner Alert\n\n{plain_message}\n\n"
            async with aiohttp.ClientSession() as session:
                payload = {"content": webhook_message}
                await session.post(self.discord_webhook_url, json=payload)
            self.discord_notifications_sent[js_url].add(plain_message)
            self.logger.debug(f"Discord notification sent for {js_url}")
        except Exception as e:
            self.logger.error(f"Discord notification error: {e}")

    async def wait_for_domain(self, domain: str):
        now = datetime.now()
        if domain in self.domain_request_times:
            elapsed = (now - self.domain_request_times[domain]).total_seconds()
            if elapsed < self.domain_wait_time:
                await asyncio.sleep(self.domain_wait_time - elapsed)
        self.domain_request_times[domain] = datetime.now()

    async def fetch(self, url: str, retry_count: int = 0) -> Optional[Dict[str, Any]]:
        parsed = urlparse(url)
        domain = parsed.netloc
        await self.wait_for_domain(domain)
        async with self.sem:
            try:
                async with self.session.get(url, ssl=self.config["verify_ssl"], allow_redirects=True) as response:
                    if response.status == 200:
                        data = await response.read()
                        charset = response.charset if response.charset else "utf-8"
                        return {
                            "content": data.decode(charset, errors="replace"),
                            "status": response.status,
                            "content_type": response.headers.get("Content-Type", "").lower(),
                            "url": str(response.url),
                            "headers": dict(response.headers)
                        }
                    else:
                        self.logger.debug(f"HTTP {response.status} for {url}")
                        return None
            except asyncio.TimeoutError:
                if retry_count < self.config["retry_limit"]:
                    self.logger.warning(f"Timeout fetching {url}. Retrying...")
                    await asyncio.sleep(2 * (retry_count + 1))
                    return await self.fetch(url, retry_count + 1)
                self.logger.error(f"Timeout after retries: {url}")
                return None
            except ClientError as e:
                self.logger.error(f"Client error for {url}: {e}")
                return None
            except Exception as e:
                self.logger.error(f"Error fetching {url}: {e}")
                if retry_count < self.config["retry_limit"]:
                    await asyncio.sleep(2 * (retry_count + 1))
                    return await self.fetch(url, retry_count + 1)
                return None

    async def run_deobfuscation(self, content: str, js_url: str) -> Tuple[str, int]:
        return await asyncio.to_thread(self.try_decode_obfuscated, content, js_url)

    def try_decode_obfuscated(self, content: str, js_url: str) -> Tuple[str, int]:
        layers = 0
        for seg in re.findall(r'["\']([A-Za-z0-9+/=]{50,})["\']', content):
            try:
                decoded = base64.b64decode(seg).decode("utf-8", errors="replace")
                if sum(c.isprintable() for c in decoded) / len(decoded) > 0.8:
                    content = content.replace(seg, decoded)
                    layers += 1
            except Exception:
                continue
        for seg in re.findall(r'["\']([A-Fa-f0-9]{40,})["\']', content):
            decoded = self.decode_hex(seg)
            if decoded != seg:
                content = content.replace(seg, decoded)
                layers += 1
        for m in re.finditer(r"String\.fromCharCode\(([0-9,\s]+)\)", content):
            try:
                nums = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
                decoded = "".join(chr(n) for n in nums)
                content = content.replace(m.group(0), f'"{decoded}"')
                layers += 1
            except Exception:
                continue
        return content, layers

    def decode_hex(self, s: str) -> str:
        try:
            decoded = bytes.fromhex(s).decode("utf-8", errors="replace")
            if sum(c.isprintable() for c in decoded) / len(decoded) > 0.8:
                return decoded
        except Exception:
            pass
        return s

    def detect_obfuscation(self, content: str) -> bool:
        score = 0
        if "eval(" in content:
            score += 1
        if "atob(" in content or "btoa(" in content:
            score += 1
        if compute_entropy(content) > 4.5:
            score += 1
        return score >= 2

    async def scan_js_content(self, content: str, context: str, js_url: str, is_inline: bool = False) -> List[ScanMatch]:
        if self.detect_obfuscation(content):
            self.logger.info(f"Obfuscated content detected in {context}. Running deobfuscation...")
            content, layers = await self.run_deobfuscation(content, js_url)
            if layers > 0:
                self.logger.info(f"Deobfuscated {layers} layer(s) in {context}.")
        matches = []
        lines = content.splitlines()
        for key, pattern in api_key_patterns.items():
            for i, line in enumerate(lines):
                for m in pattern.finditer(line):
                    snippet = m.group(1) if m.lastindex else m.group(0)
                    snippet = snippet.strip()
                    if not is_valid_token(key, snippet):
                        continue
                    entropy = compute_entropy(snippet)
                    confidence = min(1.0, (len(snippet) / 50.0) + (entropy / 10.0))
                    if confidence < 0.5:
                        continue
                    matches.append(ScanMatch(key, snippet, f"{context} (Line {i+1})", confidence, i+1, line.find(snippet)+1))
                    info = f"Detected {key} in {context}:\n{snippet} (Line {i+1}) [Entropy: {entropy:.2f}, Confidence: {confidence:.2f}]"
                    await self.send_discord_notification(js_url, info)
        return matches

    async def process_js_file(self, js_url: str) -> List[ScanMatch]:
        self.discord_notifications_sent[js_url] = set()
        fetched = await self.fetch(js_url)
        if not fetched:
            return []
        content = fetched.get("content", "")
        if content.startswith("data:application/x-javascript;base64,"):
            try:
                encoded = content.split(",", 1)[1]
                content = base64.b64decode(encoded).decode("utf-8", errors="replace")
            except Exception as e:
                self.logger.error(f"Base64 decode error for {js_url}: {e}")
                return []
        if "sourceMappingURL" in content:
            sm_url = self.extract_source_map_url(content, js_url)
            if sm_url and urlparse(sm_url).netloc == urlparse(js_url).netloc:
                self.logger.info(f"Found source map: {sm_url}")
                sm_content = await self.fetch(sm_url)
                if sm_content:
                    self.logger.info(f"Processing source map from {sm_url}")
        return await self.scan_js_content(content, f"External JS: {js_url}", js_url)

    def extract_source_map_url(self, content: str, js_url: str) -> Optional[str]:
        match = re.search(r"//# sourceMappingURL=(.+)", content)
        if match:
            sm_path = match.group(1).strip()
            return urljoin(js_url, sm_path)
        return None

    def parse_html(self, content: str) -> Any:
        try:
            from bs4 import BeautifulSoup
            if content.strip().startswith("<?xml"):
                return BeautifulSoup(content, "xml")
            return BeautifulSoup(content, "lxml")
        except Exception as e:
            self.logger.error(f"HTML parsing error: {e}")
            from bs4 import BeautifulSoup
            return BeautifulSoup(content, "html.parser")

    def extract_params_from_url(self, url: str) -> Dict[str, List[str]]:
        return parse_qs(urlparse(url).query)

    async def append_url_with_params(self, url: str) -> None:
        async with self.params_lock:
            try:
                with open(self.params_file, "a", encoding="utf-8") as f:
                    f.write(url + "\n")
                    f.flush()
                self.logger.debug(f"Appended URL with params: {url}")
            except Exception as e:
                self.logger.error(f"Error writing URL with parameters: {e}")

    # ------------------------- Worker-Based Crawling -------------------------
    async def crawl_worker(self, queue: asyncio.Queue, progress: Progress, progress_task: int):
        while True:
            try:
                url, base_domain, depth = await queue.get()
            except asyncio.CancelledError:
                break
            if url in self.visited_urls:
                queue.task_done()
                continue
            self.visited_urls.add(url)
            progress.update(progress_task, completed=len(self.visited_urls))
            fetched = await self.fetch(url)
            if fetched:
                content = fetched.get("content", "")
                soup = self.parse_html(content)
                # Process external JS files
                js_urls = [urljoin(url, s.get("src")) for s in soup.find_all("script", src=True)]
                for js_url in js_urls:
                    if urlparse(js_url).netloc == base_domain:
                        try:
                            matches = await self.process_js_file(js_url)
                            if matches:
                                self.results.add(ScanResult(url, js_url, tuple(matches)))
                        except Exception as e:
                            self.logger.error(f"Error processing JS file {js_url}: {e}")
                # Process inline scripts
                for idx, script in enumerate(soup.find_all("script", src=False)):
                    inline = script.get_text().strip()
                    if inline:
                        try:
                            matches = await self.scan_js_content(inline, f"Inline Script #{idx+1}", url, is_inline=True)
                            if matches:
                                self.results.add(ScanResult(url, f"{url} (inline #{idx+1})", tuple(matches)))
                        except Exception as e:
                            self.logger.error(f"Error processing inline script in {url}: {e}")
                # Scan entire HTML text for S3 bucket URLs and other secrets
                html_text = soup.get_text(separator=" ", strip=True)
                text_matches = scan_for_secrets(html_text, f"HTML content of {url}")
                if text_matches:
                    self.results.add(ScanResult(url, f"{url} (HTML)", tuple(text_matches)))
                # Discover and queue internal links
                for anchor in soup.find_all("a", href=True):
                    resolved = urljoin(url, anchor["href"])
                    if urlparse(resolved).netloc != base_domain:
                        continue
                    if "?" in resolved:
                        params = self.extract_params_from_url(resolved)
                        self.urls_with_params[resolved] = params
                        await self.append_url_with_params(resolved)
                    if depth < self.config["depth"] and self.is_valid_url(resolved) and resolved not in self.visited_urls:
                        queue.put_nowait((resolved, base_domain, depth + 1))
            queue.task_done()

    async def scan_websites(self, websites: List[str]):
        self.stats.start()
        self.sem = asyncio.Semaphore(self.config["concurrency"])
        connector = TCPConnector(limit=self.config["concurrency"], ssl=False)
        timeout = ClientTimeout(total=self.config["timeout"])
        async with ClientSession(connector=connector, timeout=timeout, headers=self.config["headers"]) as session:
            self.session = session
            queue: asyncio.Queue = asyncio.Queue()
            for site in websites:
                base_domain = urlparse(site).netloc
                queue.put_nowait((site, base_domain, 1))
            with Progress(
                SpinnerColumn(style="bright_green"),
                BarColumn(bar_width=40, complete_style="bright_blue"),
                TextColumn("Visited: {task.completed}"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
                transient=True
            ) as progress:
                progress_task = progress.add_task("Scanning websites...", total=None)
                workers = [asyncio.create_task(self.crawl_worker(queue, progress, progress_task))
                           for _ in range(self.config["concurrency"])]
                await queue.join()
                for w in workers:
                    w.cancel()
        self.stats.end()
        final_params_file = self.output_dir / f"urls_with_parameters_final_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(final_params_file, "w", encoding="utf-8") as f:
                json.dump(self.urls_with_params, f, indent=2)
            self.logger.info(f"Final URL collection saved to {final_params_file}")
        except Exception as e:
            self.logger.error(f"Error saving final URL collection: {e}")

    def save_results(self, output_format: str = "both") -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_data = [res.to_dict() for res in self.results]
        try:
            if output_format in ("json", "both"):
                json_file = self.output_dir / f"scan_results_{timestamp}.json"
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(json_data, f, indent=2)
            if output_format in ("txt", "both"):
                txt_file = self.output_dir / f"scan_results_{timestamp}.txt"
                with open(txt_file, "w", encoding="utf-8") as f:
                    for res in self.results:
                        f.write(f"\nWebsite: {res.website_url}\n")
                        f.write(f"Location: {res.location}\n")
                        f.write("Matches:\n")
                        for m in res.matches:
                            f.write(f"  - Type: {m.key}\n")
                            f.write(f"    Snippet: {m.snippet}\n")
                            f.write(f"    Context: {m.context}\n")
                            f.write(f"    Confidence: {m.confidence:.2f}\n")
                        f.write("-" * 80 + "\n")
            if output_format in ("html", "both"):
                html_file = self.output_dir / f"scan_results_{timestamp}.html"
                with open(html_file, "w", encoding="utf-8") as f:
                    f.write("<html><head><title>Scan Results</title></head><body>")
                    f.write(f"<h1>Scan Results - {timestamp}</h1>")
                    for res in self.results:
                        f.write(f"<h2>Website: {res.website_url}</h2>")
                        f.write(f"<h3>Location: {res.location}</h3>")
                        f.write("<ul>")
                        for m in res.matches:
                            f.write(f"<li><strong>{m.key}</strong>: {m.snippet} (Line {m.line_number}, Confidence: {m.confidence:.2f})</li>")
                        f.write("</ul><hr>")
                    f.write("</body></html>")
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
        return self.output_dir

    def is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and parsed.scheme in {"http", "https"}
        except Exception:
            return False

# ------------------------- CLI & Main Entry Point -------------------------
app = typer.Typer(help="Advanced TreasureScanner - A next-gen JavaScript scanner.")

@app.command()
def scan(
    urls: Optional[List[str]] = typer.Argument(None, help="List of website URLs to scan"),
    websites_file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="Path to a text file with website URLs (one per line)"
    ),
    depth: int = typer.Option(4, "--depth", "-d", help="Crawl depth"),
    concurrency: int = typer.Option(50, "--concurrency", "-c", help="Concurrency level"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Timeout in seconds"),
    discord_webhook: Optional[str] = typer.Option(
        None, "--discord", "-w", help="Discord webhook URL for alerts"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging")
):
    """
    Launch an advanced scan.
    
    Provide URLs as arguments, via a file, or interactively.
    """
    display_banner()
    website_list: List[str] = []
    if urls:
        website_list.extend(urls)
    elif websites_file and websites_file.exists():
        with open(websites_file, "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url and urlparse(url).scheme in {"http", "https"}:
                    website_list.append(url)
        if not website_list:
            console.print("[warning]No valid URLs found in the file.[/warning]")
            raise typer.Exit()
    else:
        load_from_file = input("Would you like to load URLs from a text file? (y/N): ").strip().lower()
        if load_from_file in {"y", "yes"}:
            file_path_input = input("Enter the file path: ").strip()
            file_path = Path(file_path_input)
            if file_path.exists():
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        url = line.strip()
                        if url and urlparse(url).scheme in {"http", "https"}:
                            website_list.append(url)
                if not website_list:
                    console.print("[warning]No valid URLs found in the file.[/warning]")
                    raise typer.Exit()
            else:
                console.print("[warning]File does not exist. Proceeding with manual input.[/warning]")
        if not website_list:
            console.print("[prompt]Enter website URLs (one per line). Submit an empty line when done:[/prompt]")
            while True:
                url = input("URL: ").strip()
                if not url:
                    break
                if urlparse(url).scheme in {"http", "https"}:
                    website_list.append(url)
                else:
                    console.print(f"[warning]Invalid URL format: {url}[/warning]")
            if not website_list:
                console.print("[warning]No websites provided. Exiting.[/warning]")
                raise typer.Exit()
    
    config = {
        "depth": depth,
        "concurrency": concurrency,
        "timeout": timeout,
        "discord_webhook_url": discord_webhook if discord_webhook else "",
        "verbose": verbose
    }
    console.print(Panel(f"[header]Configuration[/header]\nDepth: {depth}, Concurrency: {concurrency}, Timeout: {timeout} sec", style="bright_blue"))
    
    plugins: List[ScannerPlugin] = []  # Future plugin instances can be added here.
    scanner = WebsiteScanner(config, plugins)
    
    console.print(f"\n[success]Starting scan of {len(website_list)} website(s)...[/success]")
    start_time = datetime.now()
    try:
        asyncio.run(scanner.scan_websites(website_list))
    except KeyboardInterrupt:
        console.print("\n[warning]Scan aborted by user.[/warning]")
        raise typer.Exit()
    duration = (datetime.now() - start_time).total_seconds()
    output_dir = scanner.save_results("both")
    
    summary = Table(title="[success]Scan Summary[/success]", style="bright_magenta")
    summary.add_column("Metric", style="prompt")
    summary.add_column("Value", style="info")
    summary.add_row("Duration", f"{duration:.2f} sec")
    summary.add_row("Websites scanned", str(len(website_list)))
    summary.add_row("URLs visited", str(len(scanner.visited_urls)))
    summary.add_row("Matches found", str(len(scanner.results)))
    console.print(summary)
    console.print(f"\n[success]Results saved to:[/success] {output_dir}")
    console.print(f"\n[success]Realtime URL collection saved to:[/success] {scanner.params_file}")
    
    if scanner.results and typer.confirm("View detailed results summary?", default=True):
        result_table = Table(title="[header]Detailed Findings[/header]", show_lines=True)
        result_table.add_column("Website", style="info", no_wrap=True)
        result_table.add_column("Location", style="magenta")
        result_table.add_column("Matches", style="warning")
        for res in scanner.results:
            result_table.add_row(res.website_url, res.location, str(len(res.matches)))
        console.print(result_table)

if __name__ == "__main__":
    app()
