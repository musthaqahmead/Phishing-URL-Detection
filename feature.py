import ssl
import socket
from datetime import datetime, timezone
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
import whois
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse, urljoin, unquote
import certifi
import sys
import traceback
import os
import base64
from urllib3.exceptions import InsecureRequestWarning, LocationParseError
import json

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# --- Constants ---
SUSPICIOUS_KEYWORDS = [  # Expanded
    "login",
    "signin",
    "secure",
    "account",
    "update",
    "verify",
    "webscr",
    "password",
    "credential",
    "support",
    "activity",
    "security",
    "ebayisapi",
    "lucky",
    "bonus",
    "prize",
    "free",
    "confirm",
    "billing",
    "invoice",
    "payment",
    "banking",
    "admin",
    "recover",
    "unlock",
    "signin",
    "logon",
    "cmd",
    "weblogin",
    "wp-admin",
    "admincp",
    "user",
    "customer",
    "client",
    "service",
    "manage",
    "reset",
    "recovery",
    "authenticate",
    "validate",
    "signin",
    "verification",
    "live",
    "office",
    "outlook",
    "mail",  # Added more common phishing terms
]
COMMON_TLDS = {  # Expanded list
    ".com",
    ".org",
    ".net",
    ".gov",
    ".edu",
    ".io",
    ".co",
    ".uk",
    ".ca",
    ".de",
    ".jp",
    ".fr",
    ".au",
    ".us",
    ".ru",
    ".ch",
    ".it",
    ".nl",
    ".se",
    ".no",
    ".es",
    ".info",
    ".biz",
    ".name",
    ".xyz",
    ".top",
    ".club",
    ".online",
    ".site",
    ".live",
    ".app",
    ".store",
    ".shop",
    ".website",
    ".tech",
    ".space",
    ".icu",
    ".cyou",
    ".link",
    ".dev",
    ".cloud",
    ".ai",
    ".eu",
}
LEGIT_BRANDS = [  # Expanded list - ADD 'allegro' HERE
    "paypal",
    "ebay",
    "amazon",
    "apple",
    "microsoft",
    "google",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "netflix",
    "bankofamerica",
    "chase",
    "wellsfargo",
    "irs",
    "gov",
    "dhl",
    "fedex",
    "ups",
    "usps",
    "whatsapp",
    "telegram",
    "hsbc",
    "barclays",
    "standardchartered",
    "citibank",
    "capitalone",
    "americanexpress",
    "discover",
    "aliexpress",
    "alibaba",
    "target",
    "walmart",
    "costco",
    "homedepot",
    "bestbuy",
    "adobe",
    "dropbox",
    "shopify",
    "slack",
    "zoom",
    "airbnb",
    "allegro",  # Added allegro
    "youtube",
    "gmail",
    "outlook",
    "yahoo",
    "aol",
    "icloud",
    "steam",
    "discord",
    "twitch",
    "spotify",
    "wordpress",
    "blogger",
    "tumblr",
    "pinterest",
    "snapchat",
    "tiktok",
    "fandom",
    "cloudflare",
    "godaddy",
    "namecheap",
    "bluehost",
]
BLACKLIST_FILE_PATH = os.path.join("local_blacklist", "blacklist_urls.txt")


class FeatureExtraction:
    # Class variable to cache the loaded blacklist set
    _blacklist_set = None
    _blacklist_loaded = False  # Flag to prevent repeated load attempts if file missing

    def __init__(self, url):
        self.url = url
        self.whois_info = None
        self.domain_age_days = None
        self.response = None
        self.soup = None
        self.parsed_url = None
        self.scheme = "http"  # Default
        self.domain = ""
        self.path = ""
        self.query = ""
        self.api_timeout_occurred = False
        self.domain = urlparse(url).netloc
        self._fetch_page_content()
        self._initialize_url()  # Call helper method

        # Fetch only if domain seems plausible after initialization
        if self.domain and "." in self.domain and not self.domain.startswith("."):
            self._fetch_page_content()
            self._fetch_whois_info()  # Call the dedicated WHOIS fetch method
        else:
            print(
                f"Warning: Invalid/missing domain '{self.domain}' in URL '{url}'. Skipping content/WHOIS.",
                file=sys.stderr,
            )

    def check_virustotal(self, vt_api_key):  # Feature 40 (New Index)
        """Checks the URL against the VirusTotal API v3."""
        print(f"DEBUG: check_virustotal called for: {self.url}")
        if not vt_api_key:
            return 0
        urls_to_analyze = [self.url]
        if (
            self.domain
            and self.url != f"{self.scheme}://{self.domain}/"
            and self.url != f"{self.scheme}://{self.domain}"
        ):
            domain_url = f"{self.scheme}://{self.domain}/"
            if domain_url not in urls_to_analyze:
                urls_to_analyze.append(domain_url)
            print(f"DEBUG: VT - URLs to analyze: {urls_to_analyze}")
        final_result = 1
        for url in urls_to_analyze:
            print(f"DEBUG: Checking VT for: {url}")
            try:
                # Ensure URL is bytes and remove padding '=' from Base64
                url_bytes = url.encode("utf-8")
                url_id = (
                    base64.urlsafe_b64encode(url_bytes)
                    .replace(b"=", b"")
                    .decode("utf-8")
                )
            except Exception as e:
                print(f"Error creating VirusTotal URL ID: {url} {e}", file=sys.stderr)
                final_result = 0  # Neutral on error creating ID
                continue

        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"accept": "application/json", "x-apikey": vt_api_key}

        print(f"DEBUG: Querying VirusTotal endpoint: {vt_endpoint}")
        try:
            response = requests.get(vt_endpoint, headers=headers, timeout=15)

            print(f"DEBUG: VirusTotal API Response Status Code: {response.status_code}")
            if response.status_code == 429:
                print(
                    "Warning: VirusTotal API rate limit exceeded. Returning Neutral.",
                    file=sys.stderr,
                )
                return 0
            if response.status_code == 401 or response.status_code == 403:
                print(
                    "ERROR: VirusTotal API Key is invalid or forbidden.",
                    file=sys.stderr,
                )
                return 0  # Neutral - key issue
            if response.status_code == 404:
                print(f"Info: URL not found in VirusTotal database: {self.url}")
                return 0  # Safe - VT hasn't seen it / hasn't flagged it

            response.raise_for_status()  # Raise error for other non-200 codes

            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            print(
                f"DEBUG: VirusTotal Stats - Malicious: {malicious_count}, Suspicious: {suspicious_count}"
            )
            if malicious_count > 0 or suspicious_count > 0:
                print(
                    f"Info: VT flagged '{url}' as MALICIOUS/SUSPICIOUS ({malicious_count}/{suspicious_count})."
                )
                return -1
        except Timeout:
            print(
                f"Warning: Timeout during VirusTotal check for '{self.url}'",
                file=sys.stderr,
            )
            self.api_timeout_occurred = True
            final_result = 0
        except RequestException as e:
            status = e.response.status_code if e.response else "N/A"
            print(
                f"Warning: VirusTotal API request failed for '{self.url}'. Status: {status}. Reason: {e}",
                file=sys.stderr,
            )
            final_result = 0
        except Exception as e:
            print(
                f"Warning: Unexpected VirusTotal check error for '{self.url}': {e}",
                file=sys.stderr,
            )
            traceback.print_exc()
            final_result = 0
            if len(urls_to_analyze) > 1:
                time.sleep(1)
            print(f"Info: VT check complete. Final result: {final_result}")
        return final_result

    def _initialize_url(self):
        """Parses the URL and sets initial attributes."""
        try:
            decoded = self.url
            try:
                decoded = unquote(self.url)  # Attempt to decode the URL
            except Exception as decode_e:
                print(
                    f"Warning: Failed to decode URL '{self.url}': {decode_e}. Using original.",
                    file=sys.stderr,
                )

            p = urlparse(decoded)
            self.parsed_url = p
            self.scheme = p.scheme if p.scheme in ["http", "https"] else "http"
            self.domain = p.netloc.lower().strip()
            self.path = p.path
            self.query = p.query

        except Exception as e:
            print(f"ERROR: URL parsing failed for '{self.url}': {e}", file=sys.stderr)
            self.parsed_url = None
            self.scheme = "http"
            self.domain = ""
            self.path = ""
            self.query = ""

    def _fetch_page_content(self):
        """Fetches the page content and initializes BeautifulSoup."""
        if not self.domain:
            return
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "DNT": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-Ch-Ua": '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
        }
        try:
            verify_opt = certifi.where() if "certifi" in sys.modules else False
            self.response = requests.get(
                self.url,
                headers=headers,
                timeout=12,
                verify=verify_opt,
                allow_redirects=True,
            )

            if 400 <= self.response.status_code < 500:
                print(
                    f"Warning: Client Error {self.response.status_code} fetching {self.url}. Content analysis skipped.",
                    file=sys.stderr,
                )
                self.soup = None
                return  # Stop processing content for 4xx

            self.response.raise_for_status()  # Raise for 5xx

            content_type = self.response.headers.get("Content-Type", "").lower()
            if "html" in content_type:
                content_length = int(self.response.headers.get("Content-Length", 0))
                if content_length > 5 * 1024 * 1024:
                    print(f"Warning: Content > 5MB for {self.url}. Skipping soup.")
                    return
                try:
                    self.soup = BeautifulSoup(self.response.content, "lxml")
                except ImportError:
                    self.soup = BeautifulSoup(self.response.content, "html.parser")
                except Exception as parse_e:
                    print(
                        f"Warning: Soup parsing failed {self.url}: {parse_e}",
                        file=sys.stderr,
                    )
                    self.soup = None
            # else: print(f"Info: Content-Type not HTML ({content_type}) for {self.url}.")

        except Timeout:
            print(f"Warning: Timeout fetching {self.url}", file=sys.stderr)
        except ConnectionError:
            print(f"Warning: Connection error fetching {self.url}", file=sys.stderr)
        except RequestException as e:
            status = e.response.status_code if e.response is not None else "N/A"
            print(
                f"Warning: Request failed {self.url}. Status: {status}. Reason: {e}",
                file=sys.stderr,
            )
        except Exception as e:
            print(
                f"Warning: Unexpected error fetching/parsing {self.url}. Reason: {e}",
                file=sys.stderr,
            )

    def _fetch_whois_info(self):
        """Fetches WHOIS information for the domain with encoding fallback."""
        if not self.domain:
            return
        self.whois_info = None  # Ensure it's reset
        self.domain_age_days = None

        try:
            domain_part = self.domain.split(":")[0]
            domain_for_whois = domain_part.replace("www.", "")
            if not domain_for_whois or "." not in domain_for_whois:
                return

            time.sleep(0.5)
            whois_result = None
            encodings_to_try = [
                "utf-8",
                "latin-1",
                "iso-8859-1",
            ]  # Default, then common fallbacks

            for enc in encodings_to_try:
                try:
                    # Attempt to fetch WHOIS with the current encoding
                    # Note: Not all whois library forks support 'encoding' param directly.
                    # This might require modification based on your exact library version,
                    # or handling decoding *after* fetching raw bytes if the library allows.
                    # Assuming the library handles internal decoding attempts:
                    whois_result = whois.whois(domain_for_whois)
                    # If it succeeds without error using internal defaults or the hints work, break the loop
                    print(
                        f"Info: WHOIS lookup successful for '{domain_for_whois}' (tried encoding: {enc})"
                    )
                    break
                except UnicodeDecodeError:
                    print(
                        f"Info: WHOIS decode failed with {enc} for '{domain_for_whois}'. Trying next..."
                    )
                    continue  # Try the next encoding
                except whois.parser.PywhoisError as e:  # Catch library-specific errors
                    print(
                        f"W: WHOIS lib error '{domain_for_whois}': {e}", file=sys.stderr
                    )
                    whois_result = None  # Ensure result is None on this error
                    break  # Stop trying encodings if library error occurs
                except LocationParseError as e:
                    print(
                        f"W: WHOIS - Invalid hostname '{domain_for_whois}': {e}",
                        file=sys.stderr,
                    )
                    whois_result = None
                    break  # Stop trying for this domain
                except Exception as e:  # Catch broader errors during the whois call
                    print(
                        f"W: WHOIS call unexpected err '{domain_for_whois}' (encoding {enc}): {e}",
                        file=sys.stderr,
                    )
                    whois_result = None  # Ensure result is None
                    # Optionally break or continue based on error type
                    break  # Stop trying encodings on unexpected error

            # Process the result if lookup was successful
            self.whois_info = whois_result
            if self.whois_info and self.whois_info.creation_date:
                cr_date = (
                    self.whois_info.creation_date[0]
                    if isinstance(self.whois_info.creation_date, list)
                    else self.whois_info.creation_date
                )
                if isinstance(cr_date, datetime):
                    now = datetime.now(
                        cr_date.tzinfo if cr_date.tzinfo else None
                    )  # Make now offset-aware if creation_date is
                    # Use UTC if possible for reliable comparison
                    # now_utc = datetime.now(timezone.utc)
                    # cr_date_utc = cr_date.astimezone(timezone.utc) if cr_date.tzinfo else cr_date.replace(tzinfo=timezone.utc) # Assume UTC if naive
                    try:
                        self.domain_age_days = (now - cr_date).days
                    except TypeError:
                        print(f"W: Timezone issue age calc.")
                        self.domain_age_days = None
                # else: print(f"W: WHOIS creation_date type: {type(cr_date)}")

        # Catch connection/network errors outside the encoding loop
        except ConnectionResetError:
            print(f"W: WHOIS connection reset '{domain_for_whois}'.", file=sys.stderr)
        except TimeoutError:
            print(f"W: WHOIS timeout '{domain_for_whois}'.", file=sys.stderr)
        except socket.gaierror as e:
            print(f"W: WHOIS DNS error '{domain_for_whois}': {e}", file=sys.stderr)
        except AttributeError as e:
            print(
                f"W: WHOIS attribute error '{domain_for_whois}': {e}", file=sys.stderr
            )  # Often incomplete data
        except LocationParseError as e:
            print(
                f"W: WHOIS - Invalid domain format '{self.domain}': {e}",
                file=sys.stderr,
            )
        except Exception as e:
            print(
                f"W: WHOIS unexpected error '{domain_for_whois}': {e}", file=sys.stderr
            )
        # Ensure self.whois_info is None if any exception occurred outside the inner try
        if not self.whois_info:
            self.domain_age_days = None

    # --- HELPER TO LOAD BLACKLIST (Class Method) ---
    @classmethod
    def _load_blacklist(cls):
        # (Keep implementation from previous answer)
        if cls._blacklist_loaded and cls._blacklist_set is None:
            return None
        if cls._blacklist_set is not None:
            return cls._blacklist_set
        cls._blacklist_loaded = True
        loaded_set = set()
        if os.path.exists(BLACKLIST_FILE_PATH):
            print(f"Loading blacklist from: {BLACKLIST_FILE_PATH}")
            try:
                with open(
                    BLACKLIST_FILE_PATH, "r", encoding="utf-8", errors="ignore"
                ) as f:
                    count = 0
                    for line in f:
                        url = line.strip()
                        if url and not url.startswith("#"):
                            loaded_set.add(url)
                            count += 1
                print(f"Loaded {count} URLs into blacklist set.")
                cls._blacklist_set = loaded_set
            except Exception as e:
                print(
                    f"ERROR loading blacklist {BLACKLIST_FILE_PATH}: {e}",
                    file=sys.stderr,
                )
                cls._blacklist_set = None
        else:
            print(
                f"W: Blacklist file {BLACKLIST_FILE_PATH} not found. StatsReport inactive.",
                file=sys.stderr,
            )
            cls._blacklist_set = None
        return cls._blacklist_set

    # --- Feature Extraction Methods (Return -1: Unsafe, 0: Neutral, 1: Safe) ---

    def UsingIp(self):  # Feature 0
        if not self.domain:
            return 0
        try:
            ipaddress.ip_address(self.domain.split(":")[0])
            return -1
        except ValueError:
            return 1

    def longUrl(self):  # Feature 1
        l = len(self.url)
        return 1 if l < 54 else 0 if 54 <= l <= 75 else -1

    def shortUrl(self):  # Feature 2
        if not self.domain:
            return 0
        short_svcs = {
            "bit.ly",
            "goo.gl",
            "tinyurl.com",
            "t.co",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "adf.ly",
            "bit.do",
            "mcaf.ee",
            "su.pr",
            "shorte.st",
            "tiny.cc",
            "lc.chat",
            "cutt.ly",
            "rebrand.ly",
            "tny.im",
            "shor.by",
            "go.gl",
            "qr.ae",
            "cli.gs",
            "urlzs.com",
            "href.li",
        }
        return -1 if self.domain.split(":")[0].replace("www.", "") in short_svcs else 1

    def symbol(self):
        return -1 if "@" in self.url else 1  # Feature 3

    def redirecting(self):  # Feature 4
        try:
            if not self.url:
                return 0
                scheme_pos = self.url.find("://")
            if scheme_pos == -1:
                return 1
                start = scheme_pos + 3
                pos = self.url.find("//", start)
                return -1 if pos != -1 else 1
        except:
            return 0

    def prefixSuffix(self):
        return (
            0 if not self.domain else -1 if "-" in self.domain.split(":")[0] else 1
        )  # Feature 5

    def SubDomains(self):  # Feature 6
        if not self.domain:
            return 0
        dom_p = self.domain.split(":")[0]
        dots = dom_p.count(".")
        if dots <= 1:
            return 1
        if dots == 2:
            parts = dom_p.split(".")
            multi = {
                ".co.uk",
                ".org.uk",
                ".ac.uk",
                ".gov.uk",
                ".com.au",
                ".net.au",
                ".org.au",
                ".gov.au",
                ".edu.au",
                ".com.br",
                ".co.jp",
                ".co.nz",
                ".co.za",
                ".co.in",
            }
            return 1 if len(parts) > 2 and f".{parts[-2]}.{parts[-1]}" in multi else 0
        return 0 if dots == 3 else -1

    def check_https(self):
        return 1 if self.scheme == "https" else -1  # Feature 7

    def check_domain_age(self):
        return (
            0
            if self.domain_age_days is None
            else 1
            if self.domain_age_days > 180
            else -1
        )  # Feature 8

    def Favicon(self):  # Feature 9
        if not self.soup:
            print("Favicon: No soup parsed.")
            return 0
        try:
            icons = self.soup.find_all("link", rel=lambda x: x and "icon" in x.lower())
            if not icons:
                print("Favicon: No icon links found.")
                return 0
            safe = False
            for link in icons:
                href = link.get("href", "")
                if self.domain in href:
                    safe = True
                    break
            print(f"Favicon: {'Safe' if safe else 'Unsafe'}")
            return 1 if safe else -1
        except Exception as e:
            print(f"W: Favicon err: {e}")
            return 0

    def NonStdPort(self):  # Feature 10
        try:
            port = self.parsed_url.port if self.parsed_url else None
            if port is None:
                return 1
            if (self.scheme == "http" and port != 80) or (
                self.scheme == "https" and port != 443
            ):
                return -1
            return 1
        except Exception:
            return 0

    def HTTPSDomainURL(self):
        return (
            0 if not self.domain else -1 if "http" in self.domain.split(":")[0] else 1
        )  # Feature 11

    def RequestURL(self):  # Feature 12
        if not self.soup:
            return 0
        total = 0
        ext = 0
        try:
            tags = self.soup.find_all(
                ["img", "script", "video", "audio", "iframe", "embed", "source"],
                src=True,
            )
            tags += self.soup.find_all("link", href=True, rel="stylesheet")
            for t in tags:
                url_attr = t.get("src") or t.get("href")
                if url_attr and not url_attr.startswith("data:"):
                    total += 1
                    try:
                        abs_url = urljoin(self.url, url_attr)
                        req_dom = urlparse(abs_url).netloc
                        if req_dom and self.domain != req_dom:
                            ext += 1
                    except ValueError:
                        continue
            if total == 0:
                return 1
            perc = ext / float(total)
            if perc < 0.22:
                return 1
            elif perc < 0.61:
                return 0
            else:
                return -1
        except Exception as e:
            print(f"W: ReqURL err: {e}")
            return 0

    def AnchorURL(self):  # Feature 13
        if not self.soup:
            return 0
        total, ext, unsafe = 0, 0, 0
        try:
            for a in self.soup.find_all("a", href=True):
                href = a.get("href", "").strip()
                if not href:
                    continue
                total += 1
                if href.startswith("#") or href.lower().startswith(
                    ("javascript:", "mailto:", "tel:")
                ):
                    unsafe += 1
                    continue
                try:
                    abs_href = urljoin(self.url, href)
                    link_dom = urlparse(abs_href).netloc
                    if link_dom and self.domain != link_dom:
                        ext += 1
                except ValueError:
                    unsafe += 1
            eff_total = total - unsafe
            if eff_total <= 0:
                return 1 if total == 0 else 0
            perc = ext / float(eff_total)
            return 1 if perc < 0.31 else 0 if perc <= 0.67 else -1
        except Exception as e:
            print(f"W: AnchorURL err: {e}")
            return 0

    def LinksInScriptTags(self):  # Feature 14
        if not self.soup:
            return 0
        ext, total = 0, 0
        try:
            tags = self.soup.find_all(["meta", "script", "link"])
            urls = set()
            for tag in tags:
                attrs = ["content", "src", "href"]
                for attr in attrs:
                    url_str = tag.get(attr)
                    if not url_str or not isinstance(url_str, str):
                        continue
                    try:
                        potentials = re.findall(
                            r'(?:https?|ftp)://[^\s\'"<>]+', url_str
                        )
                    except:
                        continue
                    for p in potentials:
                        if p in urls:
                            continue
                        urls.add(p)
                        total += 1
                        try:
                            link_dom = urlparse(p).netloc
                        except ValueError:
                            continue
                        if link_dom and self.domain != link_dom:
                            ext += 1
            if total == 0:
                return 1
            perc = ext / float(total)
            return 1 if perc < 0.30 else 0 if perc < 0.75 else -1
        except Exception as e:
            print(f"W: LinksInScriptTags err: {e}")
            return 0

    def ServerFormHandler(self):  # Feature 15
        if not self.soup:
            return 0
        try:
            forms = self.soup.find_all("form")
            if not forms:
                return 1
            suspicious = 0
            for f in forms:
                action = f.get("action", "").strip()
                if not action or action.lower().startswith(
                    ("javascript:", "mailto:", "about:blank")
                ):
                    suspicious += 1
                    continue
                try:
                    abs_action = urljoin(self.url, action)
                    act_dom = urlparse(abs_action).netloc
                except ValueError:
                    suspicious += 1
                    continue
                if act_dom and self.domain != act_dom:
                    suspicious += 1
            if suspicious == 0:
                return 1
            perc = suspicious / float(len(forms))
            return 0 if perc < 0.5 else -1
        except Exception as e:
            print(f"W: ServerFormHandler err: {e}")
            return 0

    def InfoEmail(self):  # Feature 16
        mailto = False
        try:
            if self.soup and self.soup.find(
                "a",
                href=lambda x: isinstance(x, str) and x.lower().startswith("mailto:"),
            ):
                mailto = True
            if (
                not mailto
                and self.soup
                and self.soup.find(
                    "form",
                    action=lambda x: isinstance(x, str)
                    and x.lower().startswith("mailto:"),
                )
            ):
                mailto = True
            if (
                not mailto
                and self.response
                and self.response.text
                and re.search(r"mailto:", self.response.text, re.I)
            ):
                mailto = True
            return -1 if mailto else 1
        except Exception as e:
            print(f"W: InfoEmail err: {e}")
            return 0

    def AbnormalURL(self):  # Feature 17
        if not self.whois_info or not self.whois_info.domain_name or not self.domain:
            return 0
        try:
            reg_raw = self.whois_info.domain_name
            reg_doms = (
                [str(d).lower() for d in reg_raw]
                if isinstance(reg_raw, list)
                else [str(reg_raw).lower()]
                if reg_raw
                else []
            )
            if not reg_doms:
                return 0
            url_base = self.domain.split(":")[0].replace("www.", "")
            if url_base in reg_doms:
                return 1
            if any(url_base.endswith("." + rd) for rd in reg_doms):
                return 1
            return -1
        except Exception as e:
            print(f"W: AbnormalURL err: {e}")
            return 0

    def WebsiteForwarding(self):
        try:
            n = (
                len(self.response.history)
                if self.response and hasattr(self.response, "history")
                else 0
            )
        except:
            n = 0
        return 1 if n <= 1 else 0 if n < 4 else -1  # Feature 18

    def StatusBarCust(self):
        if not self.response or not self.response.text:
            return 0
        try:
            return (
                -1
                if re.search(
                    r"""onmouseover\s*=\s*['"]?\s*window\.status\s*=.*['"]""",
                    self.response.text,
                    re.I | re.S,
                )
                else 1
            )
        except:
            return 0  # Feature 19

    def DisableRightClick(self):
        if not self.response or not self.response.text:
            return 0
        try:
            return (
                -1
                if re.search(
                    r"""oncontextmenu\s*=\s*['"]?\s*return\s+false""",
                    self.response.text,
                    re.I,
                )
                else 1
            )
        except:
            return 0  # Feature 20

    def UsingPopupWindow(self):
        if not self.response or not self.response.text:
            return 0
        try:
            return (
                -1
                if re.search(
                    r"""(window\.open|alert|prompt)\s*\(""", self.response.text, re.I
                )
                else 1
            )
        except:
            return 0  # Feature 21

    def IframeRedirection(self):  # Feature 22
        """Checks for iframes that might be hidden or used for redirection."""
        if not self.soup:
            return 0
        try:
            for frame in self.soup.find_all("iframe"):
                style = frame.get("style", "").lower().replace(" ", "")
                if (
                    "display:none" in style
                    or "visibility:hidden" in style
                    or "opacity:0" in style
                ):
                    return -1
                try:
                    h = int(frame.get("height", "1"))
                    w = int(frame.get("width", "1"))
                except:
                    h, w = 1, 1
                if h == 0 or w == 0:
                    return -1
                if "position:absolute" in style:
                    try:
                        left_val = (
                            int(re.search(r"left:\s*(-?\d+)", style).group(1))
                            if "left:" in style
                            else 0
                        )
                        top_val = (
                            int(re.search(r"top:\s*(-?\d+)", style).group(1))
                            if "top:" in style
                            else 0
                        )
                        if left_val < -100 or top_val < -100:
                            return -1
                    except:
                        pass
            # *** ADDED: Return 1 if loop completes without finding hidden frames ***
            return 1
        except Exception as e:
            print(f"Warning: IframeRedirection error: {e}")
            return 0

    def AgeofDomain(self):
        return self.check_domain_age()  # Feature 23

    def DNSRecording(self):  # Feature 24
        if not self.domain:
            return 0
        domain_p = self.domain.split(":")[0]
        try:
            socket.getaddrinfo(domain_p, None)
            return 1
        except socket.gaierror:
            return -1
        except Exception as e:
            print(f"W: DNS check err '{domain_p}': {e}")
            return 0

    # --- Placeholders ---
    def WebsiteTraffic(self):
        return 0  # Feature 25

    def PageRank(self):
        return 0  # Feature 26

    def LinksPointingToPage(self):
        return 0  # Feature 28

    # --- IMPLEMENTED StatsReport ---
    def StatsReport(self):  # Feature 29
        """Checks URL against a locally stored blacklist feed."""
        blacklist = self._load_blacklist()  # Get cached/loaded set
        if blacklist is None:
            return 0  # Neutral if loading failed or file not found
        if self.url in blacklist:
            print(f"Info: URL '{self.url}' found in local blacklist.")
            return -1  # Unsafe
        # Optional: Check domain only (more advanced)
        # if self.domain and self.domain in blacklist_domains: return -1
        return 1  # Safe (not found)

    def GoogleIndex(self):  # Feature 27
        if self.DNSRecording() == -1:
            return -1
        if self.UsingIp() == -1:
            return -1
        return 1

    # --- Lexical Features ---
    def count_suspicious_keywords(self):  # Feature 30
        try:
            txt = (self.domain + "/" + self.path + "?" + self.query).lower()
            count = sum(k in txt for k in SUSPICIOUS_KEYWORDS)
            if count == 0:
                return 1
            elif count <= 2:
                return 0
            else:
                return -1
        except Exception as e:
            print(f"W: Keyword count err: {e}")
            return 0

    def count_special_chars(self):  # Feature 31
        try:
            txt = self.path + self.query
            safe = r'a-zA-Z0-9/.\-_~?=&%#+;,|()\[\]{}<>!$*^`\'"\\:@ '
            special = re.sub(f"[{safe}]", "", txt)
            c = len(special)
            tot = len(txt)
            if tot == 0:
                return 1
            r = c / float(tot)
            if r < 0.10:
                return 1
            elif r < 0.25:
                return 0
            else:
                return -1
        except Exception as e:
            print(f"W: Special char err: {e}")
            return 0

    def check_brand_impersonation_basic(self):  # Feature 32
        if not self.domain:
            return 0
        try:
            dom_p = self.domain.split(":")[0]
            dom_parts = dom_p.split(".")
            path_parts = [p for p in self.path.lower().split("/") if p]
            base = ""
            multi = False
            if len(dom_parts) >= 2:
                multi_chk = f".{dom_parts[-2]}.{dom_parts[-1]}"
                common_multi = {".co.uk", ".org.uk", ".com.au"}
                if multi_chk in common_multi and len(dom_parts) > 2:
                    multi = True
                    base = dom_parts[-3]
                else:
                    base = dom_parts[-2]
            elif len(dom_parts) == 1:
                base = dom_parts[0]
            sub_parts = []
            tld_len = 3 if multi else 2
            if base and len(dom_parts) > tld_len:
                sub_parts = dom_parts[:-(tld_len)]
            check_parts = sub_parts + path_parts
            for b in LEGIT_BRANDS:
                if b in check_parts and b != base:
                    print(f"Info: Brand impersonation? '{b}' in {dom_p}/{self.path}")
                    return -1
            return 1
        except Exception as e:
            print(f"W: Brand check err: {e}")
            return 0

    # --- GSB Check ---
    # --- GSB Check ---
    def check_google_safe_browsing(self, api_key):  # Feature 33
        """Checks the URL against Google Safe Browsing API."""
        print(
            f"DEBUG: check_google_safe_browsing called with key: {'*** KEY PRESENT ***' if api_key else 'None'}"
        )  # Mask key in log
        if not api_key:
            print("DEBUG: GSB check returning 0 because api_key is None or empty.")
            return 0  # Neutral if no key provided

        url_to_check = self.url
        if (
            self.domain
            and self.url != f"{self.scheme}://{self.domain}/"
            and self.url != f"{self.scheme}://{self.domain}"
        ):
            # Construct domain URL (assume https for check if original was, else http)
            domain_url = f"{self.scheme}://{self.domain}/"
            if (
                domain_url not in url_to_check
            ):  # Avoid duplicate check if url was just domain
                url_to_check.append(domain_url)

        print(f"DEBUG: GSB - URLs to check: {url_to_check}")

        endpoint = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        )
        payload = {
            "client": {
                "clientId": "yourcompany-phishing-detector",
                "clientVersion": "1.3.1",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "THREAT_TYPE_UNSPECIFIED",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url_to_check}],
            },
        }
        print(f"DEBUG: Calling GSB API for: {url_to_check}")  # Log the call attempt
        try:
            response = requests.post(
                endpoint, json=payload, timeout=8
            )  # Increased timeout slightly

            # --- ADDED LOGGING ---
            print(f"DEBUG: GSB API Response Status Code: {response.status_code}")
            response.raise_for_status()
            result = response.json()
            print(f"DEBUG: GSB API Response JSON: {result}")
            if result and result.get("matches"):
                matched_urls = [match["threat"]["url"] for match in result["matches"]]
                print(f"Info: GSB flagged unsafe. Matches found for: {matched_urls}")
                return -1
            print(f"Info: GSB check OK - No matches found for checked URLs.")
            return 1
        except Timeout:
            print(
                f"Warning: Timeout during GSB check for '{url_to_check}'",
                file=sys.stderr,
            )
            self.api_timeout_occurred = True
            return 0
        except RequestException as e:
            status = e.response.status_code if e.response is not None else "N/A"
            print(
                f"Warning: GSB API request failed for '{url_to_check}'. Status: {status}. Reason: {e}",
                file=sys.stderr,
            )
            return 0
        except Exception as e:
            print(
                f"Warning: Unexpected GSB error for '{url_to_check}': {e}",
                file=sys.stderr,
            )
            traceback.print_exc()
            return 0

    # --- Certificate Analysis ---
    def analyze_certificate(self):  # Feature 34
        if self.scheme != "https" or not self.domain:
            return 0
        dom_p = self.domain.split(":")[0]
        ctx = ssl.create_default_context(
            cafile=certifi.where() if "certifi" in sys.modules else None
        )
        conn, sock = None, None
        score = 0
        free_dv = [
            "let's encrypt",
            "cpanel",
            "zerossl",
            "sectigo rsa domain validation",
            "rapidssl",
            "ssl.com dv",
            "positivessl",
            "buypass go ssl",
            "gandi standard ssl",
        ]
        trusted = [
            "digicert",
            "sectigo",
            "globalsign",
            "entrust",
            "comodo ca limited",
            "godaddy",
            "thawte",
            "geotrust",
            "cybertrust",
            "identrust",
            "amazon",
            "google trust services",
            "microsoft rsa tls ca",
            "cloudflare",
        ]
        try:
            # Add specific catch around create_connection
            try:
                conn = socket.create_connection((dom_p, 443), timeout=5)
            except (socket.gaierror, LocationParseError) as conn_e:
                print(
                    f"W: Cert check - Cannot resolve/parse hostname '{dom_p}': {conn_e}"
                )
                return 0  # Cannot proceed if hostname is invalid for connection

            sock = ctx.wrap_socket(conn, server_hostname=dom_p)
            cert = sock.getpeercert()
            if not cert:
                return 0
            try:
                b = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(cert.get("notBefore"))
                )
                a = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(cert.get("notAfter"))
                )
                d = (a - b).days
                if d < 80:
                    score -= 2
                elif d < 180:
                    score -= 1
                elif d > 370:
                    score += 1
            except Exception as de:
                print(f"  Cert Date Err: {de}")
            try:
                iss_o, iss_cn = None, None
                if "issuer" in cert:
                    for rdn_seq in cert["issuer"]:
                        if (
                            isinstance(rdn_seq, tuple)
                            and len(rdn_seq) > 0
                            and isinstance(rdn_seq[0], tuple)
                            and len(rdn_seq[0]) > 1
                        ):
                            if rdn_seq[0][0] == "organizationName":
                                iss_o = str(rdn_seq[0][1]).lower()
                            if rdn_seq[0][0] == "commonName":
                                iss_cn = str(rdn_seq[0][1]).lower()
                iss_id = iss_cn or iss_o
                if iss_id:
                    if any(f in iss_id for f in free_dv):
                        score -= 1
                    elif any(t in iss_id for t in trusted):
                        score += 1
            except Exception as ie:
                print(f" Cert Issuer Err: {ie}")
            try:
                subj_o = None
                if "subject" in cert:
                    for rdn_seq in cert["subject"]:
                        if (
                            isinstance(rdn_seq, tuple)
                            and len(rdn_seq) > 0
                            and isinstance(rdn_seq[0], tuple)
                            and len(rdn_seq[0]) > 1
                        ):
                            if rdn_seq[0][0] == "organizationName":
                                subj_o = rdn_seq[0][1]
                                break
                if subj_o:
                    score += 2
            except Exception as se:
                print(f" Cert Subject Err: {se}")
            if score <= -2:
                return -1
            if score >= 2:
                return 1
            return 0
        except socket.gaierror:
            return 0
        except socket.timeout:
            print(f"W: Cert timeout {dom_p}")
            return 0
        except ConnectionRefusedError:
            return 0
        except ssl.SSLCertVerificationError as e:
            print(f"W: Cert verify fail {dom_p}: {e.verify_message}")
            return -1
        except ssl.SSLError as e:
            print(f"W: Cert SSL err {dom_p}: {e}")
            return 0
        except Exception as e:
            print(f"W: Cert check unexpected error {dom_p}: {e}")
            traceback.print_exc()
            return 0
        finally:
            if sock:
                sock.close()
            elif conn:
                conn.close()

    def path_depth(self):  # Feature 35
        """Calculates the depth of the URL path based on '/'."""
        try:
            # Use path from parsed_url, handle None case
            path_str = self.parsed_url.path if self.parsed_url else ""
            # Remove leading/trailing slashes for accurate counting
            path = path_str.strip("/")
            # Count '/' delimiters in the remaining path
            depth = path.count("/") if path else 0
            # Define return values based on depth thresholds
            if depth <= 1:
                return 1  # e.g., / or /page.html or /folder/
            if depth <= 3:
                return 0  # e.g., /folder/sub/page.html
            return -1  # e.g., /a/b/c/d/e/... (deep path)
        except Exception as e:
            print(f"Warning: Path depth calculation error: {e}", file=sys.stderr)
            return 0

    def suspicious_filename(self):  # Feature 36
        """Checks for suspicious filenames or extensions in the URL path."""
        try:
            path_str = self.parsed_url.path if self.parsed_url else ""
            if not path_str or path_str == "/":
                return 1  # No path or just root is safe

            # Extract filename from the path
            filename = os.path.basename(path_str.lower())  # Use lowercase
            if not filename:
                return 1
            suspicious_ext = {
                ".exe",
                ".zip",
                ".rar",
                ".js",
                ".scr",
                ".php",
                ".cmd",
                ".bat",
                ".vbs",
                ".ps1",
                ".hta",
                ".msi",
                ".dll",
            }
            suspicious_names = {
                "login",
                "update",
                "verify",
                "secure",
                "cmd",
                "account",
                "admin",
                "password",
                "recover",
                "signin",
                "confirm",
            }

            name_part, ext_part = os.path.splitext(filename)

            # Check extension
            if ext_part in suspicious_ext:
                print(f"Info: Suspicious extension detected: {ext_part}")
                return -1  # Unsafe due to extension

            # Check filename itself (exact match)
            if name_part in suspicious_names:
                print(f"Info: Suspicious filename detected: {name_part}")
                return -1  # Unsafe due to name

            # Check for very long filenames (potential obfuscation)
            if len(name_part) > 40:  # Adjusted threshold
                print(f"Info: Very long filename detected (length {len(name_part)})")
                return 0  # Neutral for long name

            return 1  # Looks safe if no suspicious patterns found
        except Exception as e:
            print(f"Warning: Suspicious filename check error: {e}", file=sys.stderr)
            return 0  # Neutral on error

    def query_length(self):  # Feature 37
        """Checks the length of the URL query string."""
        try:
            # Use query string from parsed_url
            query_str = self.parsed_url.query if self.parsed_url else ""
            q_len = len(query_str)
            # Define thresholds
            if q_len <= 20:
                return 1  # Short queries are common/safe
            if q_len <= 150:
                return 0  # Moderate length is neutral
            return -1  # Very long query string is suspicious
        except Exception as e:
            print(f"Warning: Query length check error: {e}", file=sys.stderr)
            return 0  # Neutral on error

    def count_hex_encoding(self):  # Feature 38
        """Calculates ratio of hex encoded characters (%) in path + query."""
        try:
            # Use path and query from parsed_url
            path_str = self.parsed_url.path if self.parsed_url else ""
            query_str = self.parsed_url.query if self.parsed_url else ""
            text_to_check = path_str + query_str

            if not text_to_check:
                return 1
            hex_matches = re.findall(r"%[0-9a-fA-F]{2}", text_to_check)
            count = len(hex_matches)
            total_len = len(text_to_check)

            ratio = count / float(total_len) if total_len > 0 else 0

            # Define thresholds based on ratio
            if ratio == 0:
                return 1  # Safe if no hex encoding
            if ratio < 0.05:
                return 0  # Neutral for low ratio (< 5%)
            return -1  # Unsafe for higher ratio (>= 5%)
        except Exception as e:
            print(f"Warning: Hex encoding count error: {e}", file=sys.stderr)
            return 0

    def form_analysis(self):  # Feature 39
        """Analyzes forms for password fields and autocomplete settings."""
        if not self.soup:
            return 0  # Neutral if no HTML content parsed
        try:
            forms = self.soup.find_all("form")
            if not forms:
                return 1  # Safe if no forms found

            password_fields_count = 0
            autocomplete_off_on_pwd = False
            external_action_forms = 0  # Count forms submitting externally

            for form in forms:
                # Check action (reuse part of ServerFormHandler logic)
                action = form.get("action", "").strip()
                is_external_action = False
                if action and not action.lower().startswith(
                    ("javascript:", "mailto:", "about:blank", "#")
                ):
                    try:
                        absolute_action = urljoin(self.url, action)
                        action_domain = urlparse(absolute_action).netloc
                        if action_domain and self.domain != action_domain:
                            is_external_action = True
                    except ValueError:
                        is_external_action = (
                            True  # Treat invalid action as external/suspicious
                        )
                elif not action or action.lower().startswith(
                    ("javascript:", "mailto:")
                ):  # Also count empty/js/mailto as potentially risky
                    is_external_action = True

                if is_external_action:
                    external_action_forms += 1

                # Check input fields within the form
                inputs = form.find_all("input")
                for inp in inputs:
                    inp_type = inp.get("type", "").lower()
                    if inp_type == "password":
                        password_fields_count += 1
                        if inp.get("autocomplete", "").lower() == "off":
                            autocomplete_off_on_pwd = True

            # --- Determine Feature Score ---
            # Condition 1: Password field exists AND autocomplete is off
            if password_fields_count > 0 and autocomplete_off_on_pwd:
                print("Info: Form has password field with autocomplete=off")
                return -1

            if password_fields_count > 1:  # Threshold lowered to > 1
                print(
                    f"Info: Page has multiple ({password_fields_count}) password fields"
                )
                return -1  # Unsafe

            if external_action_forms > 0 and password_fields_count > 0:
                print("Info: Form has password field AND submits externally")
                return -1  # Unsafe pattern

            # Condition 4: Only password field(s) present, submits internally, autocomplete not off
            if password_fields_count > 0:
                return 0  # Neutral - Presence of password field isn't inherently bad

            # Condition 5: No password fields found
            return 1  # Safe if no forms handled passwords suspiciously

        except Exception as e:
            print(f"Warning: Form analysis error: {e}", file=sys.stderr)
            return 0  # Neutral on error

    # --- Main Method to Get All Features ---
    def getFeaturesList(self, api_key=None, vt_api_key=None):
        """Extracts and returns all features in the defined order."""
        # Load blacklist once if not already loaded
        if not FeatureExtraction._blacklist_loaded:
            FeatureExtraction._load_blacklist()

        # Define the order of feature extraction methods
        feature_extraction_methods = [
            self.UsingIp,
            self.longUrl,
            self.shortUrl,
            self.symbol,
            self.redirecting,  # 0-4
            self.prefixSuffix,
            self.SubDomains,
            self.check_https,
            self.check_domain_age,
            self.Favicon,  # 5-9
            self.NonStdPort,
            self.HTTPSDomainURL,
            self.RequestURL,
            self.AnchorURL,
            self.LinksInScriptTags,  # 10-14
            self.ServerFormHandler,
            self.InfoEmail,
            self.AbnormalURL,
            self.WebsiteForwarding,
            self.StatusBarCust,  # 15-19
            self.DisableRightClick,
            self.UsingPopupWindow,
            self.IframeRedirection,
            self.AgeofDomain,
            self.DNSRecording,  # 20-24
            self.WebsiteTraffic,
            self.PageRank,
            self.GoogleIndex,
            self.LinksPointingToPage,
            self.StatsReport,  # 25-29
            self.count_suspicious_keywords,
            self.count_special_chars,
            self.check_brand_impersonation_basic,  # 30-32
            lambda: self.check_google_safe_browsing(api_key),  # 33
            self.analyze_certificate,  # 34
            self.path_depth,  # 35
            self.suspicious_filename,  # 36
            self.query_length,  # 37
            self.count_hex_encoding,  # 38
            self.form_analysis,  # 39
            lambda: self.check_virustotal(vt_api_key),  # 40 <-- VirusTotal Check
        ]
        features = []
        print(f"--- Starting Feature Extraction for: {self.url} ---")
        for i, method in enumerate(feature_extraction_methods):
            feature_name = getattr(method, "__name__", f"lambda_feature_{i}")
            try:
                feature_value = method()
                if feature_value not in [-1, 0, 1]:
                    print(
                        f"Warning: Feature {feature_name} ({i}) invalid value '{feature_value}'. Using 0.",
                        file=sys.stderr,
                    )
                    feature_value = 0
                features.append(feature_value)
            except Exception as e:
                print(
                    f"ERROR executing feature {feature_name} ({i}): {e}",
                    file=sys.stderr,
                )
                traceback.print_exc()
                features.append(0)

        domain_to_append = self.domain if isinstance(self.domain, str) else ""
        features.append(domain_to_append)

        expected_length = len(feature_extraction_methods) + 1
        if len(features) != expected_length:
            print(
                f"FATAL ERROR: Final feature vector length mismatch! Expected {expected_length}, Got {len(features)}",
                file=sys.stderr,
            )

        print(
            f"--- Finished Feature Extraction. Vector length: {len(features)} (Features: {len(features) - 1}, Domain: 1) ---"
        )
        return features
