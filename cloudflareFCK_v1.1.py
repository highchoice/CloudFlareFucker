import argparse
import requests
from termcolor import colored
from bs4 import BeautifulSoup
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common headers that simulate a real browser
BROWSER_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
    'TE': 'trailers',
}

def create_session(proxy=None, cookies=None):
    session = requests.Session()
    
    # Configure retry strategy
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Configure proxy if provided
    if proxy:
        session.proxies = {
            "http": proxy,
            "https": proxy
        }
    
    # Set cookies if provided
    if cookies:
        session.cookies.update(cookies)
    
    return session

def get_page_info(url, headers, session=None, debug=False):
    try:
        if not session:
            session = create_session()
        
        # Add random delay to avoid rate limiting
        time.sleep(random.uniform(1, 3))
        
        # Merge our standard browser headers with the specific ones
        final_headers = {**BROWSER_HEADERS, **headers}
        
        response = session.get(
            url,
            headers=final_headers,
            timeout=10,
            verify=False
        )

        if debug:
            print(colored(f"\nRequest to {url}:", 'cyan'))
            print(f"Headers:\n{response.request.headers}")
            print(colored(f"\nResponse from {url}:", 'cyan'))
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers:\n{response.headers}")
            print(f"Response Content:\n{response.text[:1000]}...")

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string.strip() if soup.title else None
            h1_tags = [h1.get_text(strip=True) for h1 in soup.find_all('h1')]
            return {
                'title': title,
                'content_length': len(response.content),
                'h1_tags': h1_tags,
                'status_code': response.status_code,
                'cookies': session.cookies.get_dict()
            }
        elif response.status_code in [403, 503, 429, 405]:
            if debug:
                print(colored(f"Cloudflare block detected for {url}. Status code: {response.status_code}", 'red'))
                print(f"Response headers: {response.headers}")
            return None
    except Exception as e:
        if debug:
            print(colored(f"Request failed for {url}: {str(e)}", 'red'))
        return None

def compare_responses(original_info, ip_info, ip, protocol, port, verbose=False):
    matched_criteria = []
    details = []

    if ip_info['content_length'] == original_info['content_length']:
        matched_criteria.append("Content-Length")
        details.append(f"Content-Length: {original_info['content_length']}")
    if ip_info['title'] == original_info['title']:
        matched_criteria.append("Title")
        details.append(f"Title: {original_info['title']}")
    if ip_info['h1_tags'] == original_info['h1_tags']:
        matched_criteria.append("H1 Tags")
        details.append(f"H1 Tags: {', '.join(original_info['h1_tags']) if original_info['h1_tags'] else 'None'}")

    if len(matched_criteria) == 3:
        if verbose:
            print(colored(f"Real IP found: {ip} on {protocol.upper()} (Port {port})", 'green'))
            print(f"Matched Criteria: {', '.join(matched_criteria)}")
            print(f"Details:\n{chr(10).join(details)}")
        else:
            print(colored(f"Real IP found: {ip} on {protocol.upper()} (Port {port})", 'green'))
    elif matched_criteria:
        diff_criteria = set(["Content-Length", "Title", "H1 Tags"]) - set(matched_criteria)
        print(colored(f"Possible IP found: {ip} on {protocol.upper()} (Port {port})", 'yellow'))
        print(f"Matched: {', '.join(matched_criteria)} | Differed: {', '.join(diff_criteria)}")
        print(f"Details:\n{chr(10).join(details)}")

def check_single_ip(ip, domain, original_info, ports, proxy=None, debug=False, verbose=False, cookies=None):
    session = create_session(proxy, cookies)
    
    for port in ports:
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{ip}:{port}/"
        headers = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Referer': f'https://{domain}/'
        }

        response_info = get_page_info(url, headers, session, debug)

        if response_info:
            compare_responses(original_info, response_info, ip, protocol, port, verbose)

def check_ip_in_threads(domain, ip_list_file, original_info, ports, proxy=None, threads=5, debug=False, verbose=False, cookies=None):
    with open(ip_list_file, 'r') as file:
        ips = [line.strip() for line in file if line.strip()]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(check_single_ip, ip, domain, original_info, ports, proxy, debug, verbose, cookies)
            for ip in ips
        ]

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                if debug:
                    print(colored(f"Error processing IP: {str(e)}", 'red'))

def main():
    parser = argparse.ArgumentParser(description="Check a domain behind Cloudflare against a list of IPs.")
    parser.add_argument('-d', '--domain', required=True, help='The domain to check.')
    parser.add_argument('-iplist', '--iplist', required=True, help='File path to the list of IP addresses.')
    parser.add_argument('--proxy', required=False, help='Optional proxy for requests (e.g., http://127.0.0.1:8080).')
    parser.add_argument('--threads', required=False, type=int, default=5, help='Number of threads to use (default: 5).')
    parser.add_argument('--debug', required=False, action='store_true', help='Prints request and response details for debugging.')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='Enable verbose output for matched criteria.')
    parser.add_argument('--port', required=False, type=int, nargs='+', help='Specify port(s) to test. If not provided, default ports 80 and 443 are used.')
    parser.add_argument('--cookies', required=False, help='Cookies to use (e.g., "cf_clearance=YOUR_CLEARANCE_COOKIE").')

    args = parser.parse_args()

    ports = args.port if args.port else [80, 443]
    
    # Parse cookies if provided
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value

    print(f"Fetching original content from {args.domain}...")
    headers = {
        'Host': args.domain,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': f'https://{args.domain}/'
    }
    
    # Try with session to maintain cookies
    session = create_session(args.proxy, cookies)
    
    # Try both HTTP and HTTPS in case one is blocked
    for protocol in ['https', 'http']:
        original_info = get_page_info(f"{protocol}://{args.domain}/", headers, session, args.debug)
        if original_info:
            break
    
    if original_info:
        print(f"Original info: Content-Length={original_info['content_length']}, Title={original_info['title']}, H1 Tags={original_info['h1_tags']}")
        # Update cookies with any new ones received
        if original_info.get('cookies'):
            cookies.update(original_info['cookies'])
    else:
        print("Failed to fetch the original page content. Exiting...")
        sys.exit(1)

    try:
        check_ip_in_threads(
            args.domain,
            args.iplist,
            original_info,
            ports,
            args.proxy,
            args.threads,
            args.debug,
            args.verbose,
            cookies
        )
    except KeyboardInterrupt:
        while True:
            user_input = input("\nCTRL+C detected. Do you want to quit (q) or continue (c)? ").lower()
            if user_input == 'q':
                print("Quitting...")
                sys.exit(0)
            elif user_input == 'c':
                print("Continuing...")
                break

if __name__ == "__main__":
    while True:
        try:
            main()
            break
        except KeyboardInterrupt:
            continue