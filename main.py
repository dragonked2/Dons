import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import logging
import urllib3

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
    "Microsoft API Key": r"(?i)microsoft.*['|\"][0-9a-f]{22}['|\"]",
    "YouTube API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Reddit Client ID": r"(?i)reddit(.{0,20})?['\"][0-9a-zA-Z-_]{14}['\"]",
    "Instagram Access Token": r"(?i)instagram(.{0,20})?['\"][0-9a-zA-Z-_]{7}['\"]",
    "Docker Registry Token": r"(?i)docker[^\s]*?['|\"]\w{32,64}['|\"]",
    "GitHub Personal Access Token": r"[a-f0-9]{40}",
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
    "DigitalOcean API Token": r"([a-f0-9]{64})",
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
    "Imgur Client ID": r"(?i)imgur.*['|\"]\w{12}['|\"]",
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
    "AWS IAM Access Key": r"(?i)aws.*['|\"]\w{20}['|\"]",
    "AWS IAM Secret Key": r"(?i)aws.*['|\"]\w{40}['|\"]",
    "Twilio API Key": r"(?i)twilio.*['|\"]\w{32}['|\"]",
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
}


class WebsiteScanner:
    DEFAULT_DEPTH = 4

    def __init__(self, depth=None):
        self.depth = depth or self.DEFAULT_DEPTH
        self.results = set()

    def is_same_domain(self, base_url, target_url):
        return urlparse(base_url).netloc == urlparse(target_url).netloc

    def get_urls_from_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            raise

    def crawl_and_scan(self, url, base_url):
        if self.depth <= 0 or not self.is_same_domain(base_url, url):
            return

        try:
            response = requests.get(url, verify=False, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            js_urls = [urljoin(url, script['src']) for script in soup.find_all('script', src=True)]

            for js_url in tqdm(js_urls, desc=f"Scanning JavaScript files at {url}", position=0, leave=False):
                try:
                    matches = self.scan_js_file(js_url)
                    if matches:
                        result_key = (js_url, tuple(matches))
                        if result_key not in self.results:
                            self.results.add(result_key)
                            self.display_matches(js_url, matches)

                except requests.exceptions.RequestException as ex:
                    logging.error(f"Error scanning {js_url}: {ex}")

            next_depth_urls = [urljoin(url, link['href']) for link in soup.find_all('a', href=True)]
            with ThreadPoolExecutor() as executor:
                executor.map(self.crawl_and_scan, next_depth_urls, [url] * len(next_depth_urls))

        except requests.exceptions.RequestException as e:
            logging.error(f"Error accessing {url}: {e}")
            print(f"Error accessing {url}: {e}")
        except Exception as ex:
            logging.error(f"An unexpected error occurred: {ex}")
            print(f"An unexpected error occurred: {ex}")

    def scan_js_file(self, js_url):
        try:
            response = requests.get(js_url, verify=False, timeout=10)
            response.raise_for_status()

            js_content = response.text
            results = []

            for key, pattern in regex_patterns.items():
                if isinstance(pattern, str):
                    matches = re.finditer(pattern, js_content)
                    for match in matches:
                        start = max(0, match.start() - 50)
                        end = min(len(js_content), match.end() + 50)
                        snippet = js_content[start:end].strip()
                        results.append((key, snippet))

            return results

        except requests.exceptions.RequestException as e:
            logging.error(f"Error accessing {js_url}: {e}")
            print(f"Error accessing {js_url}: {e}")
            return []
        except Exception as ex:
            logging.error(f"An unexpected error occurred while scanning {js_url}: {ex}")
            return []

    def display_matches(self, url, matches):
        print(f"\nMatches found at {url}:")

        if matches:
            for key, snippet in matches:
                print(f"  Key: {key}")
                print(f"    Snippet: {snippet}\n" if snippet else f"    Snippet: [Unable to retrieve snippet]")
        else:
            print("  No matches found.")

    def scan_websites(self, websites):
        with ThreadPoolExecutor() as executor:
            for website in tqdm(websites, desc="Scanning websites", position=1):
                print(f"\nScanning website: {website}\n")
                try:
                    self.crawl_and_scan(website, website)
                except Exception as ex:
                    logging.error(f"An error occurred while scanning {website}: {ex}")
                    print(f"An error occurred while scanning {website}: {ex}")

def main():
    try:
        file_or_single = input("Scan multiple websites from a file or a single website? (Enter 'file' or 'single'): ").lower()

        if file_or_single == 'file':
            file_path = input("Enter the path to the file containing website URLs: ")
            try:
                websites = WebsiteScanner().get_urls_from_file(file_path)
            except FileNotFoundError:
                print("File not found. Exiting.")
                return
        elif file_or_single == 'single':
            website = input("Enter the website URL: ")
            websites = [website]
        else:
            print("Invalid input. Exiting.")
            return

        depth = int(input(f"Enter the recursive depth for scanning (default is {WebsiteScanner.DEFAULT_DEPTH}): ") or WebsiteScanner.DEFAULT_DEPTH)

        print(f"\nScanning {len(websites)} website(s) with recursive depth of {depth}...\n")

        scanner = WebsiteScanner(depth=depth)
        scanner.scan_websites(websites)

        print("\nScanning completed.")

    except KeyboardInterrupt:
        print("\nScanning interrupted by the user.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        print(f"Request error: {e}")
    except Exception as ex:
        logging.error(f"An error occurred: {ex}")
        print(f"An error occurred: {ex}")

if __name__ == "__main__":
    main()
