import asyncio
import os
import logging
import time
from aiohttp import ClientSession
from requests import get
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from rich.console import Console
from jsbeautifier import beautify
from re import findall

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

regex_list = {
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Artifactory API Token": r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}',
    "Artifactory Password": r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}',
    "Cloudinary Basic Auth": r"cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+",
    "Firebase Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "LinkedIn Secret Key": r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
    "Mailto String": r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+",
    "Firebase URL": r".*firebaseio\.com",
    "PGP Private Key Block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "SSH (DSA) Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "SSH (RSA) Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (ssh-ed25519) Public Key": r"ssh-ed25519",
    "Google Captcha Key": r"6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$",
    "Amazon AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Amazon MWS Auth Token": (
        r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ),
    "Amazon AWS API Key": r"AKIA[0-9A-Z]{16}",
    "Amazon AWS URL": r"s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com",
    "Generic API Key": r"(?i)api[_]?key.*['|\"]\w{32,45}['|\"]",
    "Generic Secret": r"(?i)secret.*['|\"]\w{32,45}['|\"]",
    "Authorization Bearer": r"bbearer [a-zA-Z0-9_\\-\\.=]+",
    "Authorization Basic": r"basic [a-zA-Z0-9=:_\+\/-]{5,100}",
    "Authorization API Key": r"api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}",
    "PayPal Braintree Access Token": (
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
    ),
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Heroku API Key": (
        r"(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
    ),
    "JWT Token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"(?i)facebook.*['|\"][0-9a-f]{32}['|\"]",
    "Google OAuth": r"ya29\.[0-9A-Za-z\-_]+",
    "Facebook Client ID": r"""(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}""",
    "Google Cloud Platform API Key": (
        r"(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|\"|\n|\r|\s|\x60]|$)"
    ),
    "Google Cloud Platform OAuth": (
        r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
    ),
    "Google Drive API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google Drive OAuth": (
        r"(?i)client.*(['\"]).*?client_id['\"]\s*:\s*['\"](.*?)[0-9]-[a-z]{16}['\"]"
    ),
    "Google Gmail API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google Gmail OAuth": (
        r"(?i)client.*(['\"]).*?client_id['\"]\s*:\s*['\"](.*?)[0-9]-[a-z]{16}['\"]"
    ),
    "Google Maps API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google Maps OAuth": (
        r"(?i)client.*(['\"]).*?client_id['\"]\s*:\s*['\"](.*?)[0-9]-[a-z]{16}['\"]"
    ),
    "Google Play Android Developer API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google Play Android Developer OAuth": (
        r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
    ),
    "Google Play Services API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google Play Services OAuth": (
        r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
    ),
    "Google Street View Image API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google Street View Image OAuth": (
        r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
    ),
    "Slack API Key": r"(?i)slack.*['|\"][0-9a-zA-Z-]+['|\"]",
    "Stripe Standard API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishing API Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Telegram Bot API Key": r"[0-9]+:[a-zA-Z0-9_-]+",
    "Twilio API Key": r"(?i)twilio.*['|\"][0-9a-f]{32}['|\"]",
    "Twitter Access Token": r"(?i)twitter.*['|\"][0-9a-z]{35,44}['|\"]",
    "Twitter OAuth": r"(?i)twitter.*['|\"][0-9a-z]{35,44}['|\"]",
    "Twitter API Key": r"(?i)twitter.*['|\"][0-9a-z]{35,44}['|\"]",
    "Windows Live API Key": r"(?i)windowslive.*['|\"][0-9a-f]{22}['|\"]",
    "Microsoft API Key": r"(?i)microsoft.*['|\"][0-9a-f]{22}['|\"]",
    "Microsoft Azure Data Explorer (Kusto) API Key": r"fed=.*",
    "YouTube API Key": r"AIza[0-9A-Za-z-_]{35}",
    "YouTube OAuth": r"(?i)youtube.*['|\"][0-9a-z]{25}['|\"]",
    "Reddit Client ID": r"(?i)reddit(.{0,20})?['\"][0-9a-zA-Z-_]{14}['\"]",
    "Instagram Access Token": r"(?i)instagram(.{0,20})?['\"][0-9a-zA-Z-_]{7}['\"]",
    "Foursquare API Key": r"(?i)foursquare.*['|\"][0-9a-zA-Z]{48}['|\"]",
    "OpenID Connect Generic Provider API Key": (
        r"['|\"]?authorization_endpoint['|\"](.{1,50})?['|\"](.*?)[a-z0-9_-]+['|\"]"
    ),
    "Generic OAuth 2.0": r"(?i)(oauth|open\W*source).*['|\"]?([a-z0-9_-]+)['|\"]",
    "Bearer Token": r"['|\"]?token['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?",
    "Basic Auth Credentials": (
        r"(?i)basic.*['|\"]?[a-zA-Z0-9-_]+['|\"]?:['|\"]?[a-zA-Z0-9-_]+['|\"]?"
    ),
    "Generic API Token": (
        r"['|\"]?api[_]?key['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?"
    ),
    "Generic API Secret": (
        r"['|\"]?api[_]?secret['|\"]?\s*[:=]\s*['|\"]?([a-zA-Z0-9-_]+)['|\"]?"
    ),
}


class SecretScanner:
    def __init__(self):
        self.console = Console()
        self.scanned_urls = set()

    def display_result(self, key, link, matches, js_file=None):
        self.console.print(f"\n[bold green][+] {key} found in {link}[/bold green]")
        if js_file:
            self.console.print(f"[cyan]Found in JavaScript file:[/cyan] {js_file}")
        self.console.print(f"[red]Matches:[/red] {matches}\n")

    def scan_js_content(self, content, link, js_file=None):
        content = beautify(content)
        results = []
        for key, pattern in regex_list.items():
            matches = findall(pattern, content)
            if matches:
                self.display_result(key, link, matches, js_file=js_file)
                results.append(f"{key} found in {link}: {matches}")
        return results

    async def fetch(self, url, session):
        try:
            async with session.get(url) as response:
                return await response.text()
        except Exception as e:
            self.log_error(f"Error fetching {url}", exception=e)
            return ""

    async def scan_js_links_async(self, links, base_url):
        async with ClientSession() as session:
            tasks = [self.fetch(urljoin(base_url, link), session) for link in links]
            return await asyncio.gather(*tasks)

    def extract_js_links(self, html_content, base_url):
        soup = BeautifulSoup(html_content, "html.parser")
        js_links = [
            script.get("src") for script in soup.find_all("script", {"src": True})
        ]
        return js_links

    def filter_external_links(self, base_url, links):
        parsed_base_url = urlparse(base_url)
        return [
            link for link in links if parsed_base_url.netloc == urlparse(link).netloc
        ]

    async def crawl_and_scan(self, url):
        try:
            if url in self.scanned_urls:
                return []

            self.scanned_urls.add(url)

            response = get(url, timeout=30, allow_redirects=True)
            content_type = response.headers.get("Content-Type", "").lower()

            if "text/html" in content_type:
                html_content = response.text
                js_links = self.extract_js_links(html_content, url)
                js_links = self.filter_external_links(url, js_links)

                self.console.print(
                    f"\n[bold]Scanning {url} for sensitive information...[/bold]\n"
                )
                time.sleep(1)

                results = self.scan_js_content(html_content, url)
                loop = asyncio.get_event_loop()
                link_results = await self.scan_js_links_async(js_links, url)
                for link, result in zip(js_links, link_results):
                    self.console.print(
                        f"\n[bold]Scanning {link} for sensitive information...[/bold]\n"
                    )
                    results.extend(result)

                return results
            else:
                self.console.print(
                    f"[yellow]Skipping {url} (Not HTML content)[/yellow]"
                )
                return []
        except RequestException as e:
            self.log_error(f"Error accessing {url}", exception=e)
            return []
        except Exception as e:
            self.log_error(f"An unexpected error occurred", exception=e)
            return []

    def welcome_message(self):
        ascii_art_logo = """
        ██████╗  ██████╗ ███╗   ██╗███╗   ██╗███████╗
        ██╔══██╗██╔═══██╗████╗  ██║████╗  ██║██╔════╝
        ██║  ██║██║   ██║██╔██╗ ██║██╔██╗ ██║███████╗
        ██║  ██║██║   ██║██║╚██╗██║██║╚██╗██║╚════██║
        ██████╔╝╚██████╔╝██║ ╚████║██║ ╚████║███████║
        ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝
        """
        self.console.print(f"[bold magenta]{ascii_art_logo}[/bold magenta]")
        self.console.print("[cyan][bold]Welcome to the Secret Scanner![/bold][/cyan]\n")
        self.console.print(
            "This tool scans JavaScript files for sensitive information."
        )
        self.console.print(
            "It can find API keys, credentials, and other secrets embedded in the"
            " code.\n"
        )

    def scan_complete_message(self):
        self.console.print("[cyan][bold]Scan complete![/bold][/cyan]")
        self.console.print("Thank you for using the Secret Scanner.")

    def save_results(self, results, output_dir="scan_results"):
        os.makedirs(output_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d%H%M%S")
        output_file = os.path.join(output_dir, f"scan_results_{timestamp}.txt")
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for result in results:
                    f.write(result + "\n")
            self.console.print(f"[cyan]Results saved to {output_file}[/cyan]")
        except Exception as e:
            self.log_error(f"Error saving results to {output_file}", exception=e)

    def run(self, start_url):
        self.welcome_message()
        loop = asyncio.get_event_loop()
        try:
            results = loop.run_until_complete(self.crawl_and_scan(start_url))
            self.scan_complete_message()
            if results:
                self.save_results(results)
        except Exception as e:
            self.log_error(f"An unexpected error occurred", exception=e)

    def log_error(self, message, exception=None):
        if exception is not None:
            logger.error(f"{message}. Exception: {str(exception)}")
        else:
            logger.error(message)


if __name__ == "__main__":
    try:
        scanner = SecretScanner()
        mode = input(
            "Do you want to scan a single website (S) or a list of websites from a file"
            " (L)? "
        ).upper()
        if mode == "S":
            start_url = input("Enter the starting URL to scan: ")
            scanner.run(start_url)
        elif mode == "L":
            file_path = input(
                "Enter the path to the text file containing the list of websites: "
            )
            with open(file_path, "r") as file:
                websites = file.read().splitlines()
            for website in websites:
                scanner.run(website)
        else:
            print(
                "Invalid mode. Please enter 'S' for a single website or 'L' for a list"
                " of websites."
            )
    except Exception as e:
        scanner.log_error(f"An unexpected error occurred", exception=e)
