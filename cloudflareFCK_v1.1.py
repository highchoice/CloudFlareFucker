import argparse
import requests
from termcolor import colored
from bs4 import BeautifulSoup
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import random

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_original_info_selenium(domain):
    print(colored("\n[+] Getting original info using Selenium...", 'blue'))
    
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36")
    
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        # Probamo prvo HTTPS
        url = f"https://{domain}"
        driver.get(url)
        
        # Čekamo da se title pojavi (Cloudflare ima delay)
        WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.TAG_NAME, 'title')))
        
        # Random delay da izgleda kao ljudska interakcija
        time.sleep(random.uniform(1, 3))
        
        page_source = driver.page_source
        soup = BeautifulSoup(page_source, 'html.parser')
        
        title = soup.title.string.strip() if soup.title else None
        h1_tags = [h1.get_text(strip=True) for h1 in soup.find_all('h1')]
        #content_length = len(page_source)
        
        
        # Čitanje Content-Length iz headera preko JavaScript-a
        content_length = driver.execute_script(
            "return performance.getEntries()[0].transferSize || "
            "performance.getEntries()[0].encodedBodySize || "
            "document.documentElement.innerHTML.length"
        )       
        
        
        
        print(colored("[+] Successfully retrieved original info with Selenium", 'green'))
        print(f"Title: {title}")
        print(f"Content Length: {content_length}")
        print(f"H1 Tags: {h1_tags}")
        
        return {
            'title': title,
            'content_length': int(content_length),
            'h1_tags': h1_tags
        }
        
    except Exception as e:
        print(colored(f"[-] Error getting original info: {str(e)}", 'red'))
        return None
    finally:
        driver.quit()

def get_page_info(url, headers, proxies=None, debug=False):
    try:
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)

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
                #'content_length': int(response.headers.get('Content-Length', len(response.content))),                
                'h1_tags': h1_tags,
                'status_code': response.status_code
            }
    except requests.RequestException as e:
        if debug:
            print(colored(f"Request failed: {str(e)}", 'red'))
        return None

def compare_responses(original_info, ip_info, ip, protocol, port, verbose=False):
    matched_criteria = []
    details = []
    content_length_diff = 0
    
    # Provera Content-Length sa tolerancijom ±50
    if 'content_length' in ip_info and 'content_length' in original_info:
        content_length_diff = abs(ip_info['content_length'] - original_info['content_length'])
        if content_length_diff <= 1000:
            matched_criteria.append("Content-Length")
            details.append(f"Content-Length: {original_info['content_length']} (diff: {content_length_diff})")
    
    # Provera Title
    if 'title' in ip_info and 'title' in original_info:
        if ip_info['title'] == original_info['title']:
            matched_criteria.append("Title")
            details.append(f"Title: {original_info['title']}")
    
    # Provera H1 Tags
    if 'h1_tags' in ip_info and 'h1_tags' in original_info:
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
        match_status = colored("Strong match", 'green') if len(matched_criteria) >= 2 else colored("Partial match", 'yellow')
        
        print(colored(f"Possible IP found: {ip} on {protocol.upper()} (Port {port}) - {match_status}", 'yellow'))
        print(f"Matched: {', '.join(matched_criteria)} | Differed: {', '.join(diff_criteria)}")
        if content_length_diff > 0:
            print(f"Content-Length difference: {content_length_diff} characters")
        print(f"Details:\n{chr(10).join(details)}")

def check_single_ip(ip, domain, original_info, ports, proxy=None, debug=False, verbose=False):
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    for port in ports:
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{ip}:{port}/"
        headers = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36'
        }

        response_info = get_page_info(url, headers, proxies, debug)

        if response_info:
            compare_responses(original_info, response_info, ip, protocol, port, verbose)

def check_ip_in_threads(domain, ip_list_file, original_info, ports, proxy=None, threads=5, debug=False, verbose=False):
    with open(ip_list_file, 'r') as file:
        ips = [line.strip() for line in file if line.strip()]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(check_single_ip, ip, domain, original_info, ports, proxy, debug, verbose)
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

    args = parser.parse_args()

    ports = args.port if args.port else [80, 443]

    # Step 1: Get original info using Selenium (only for the initial reference)
    original_info = get_original_info_selenium(args.domain)
    if not original_info:
        print("Failed to get original page info. Exiting...")
        sys.exit(1)

    # Step 2: Check IPs using the original method
    try:
        check_ip_in_threads(args.domain, args.iplist, original_info, ports, args.proxy, args.threads, args.debug, args.verbose)
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
    main()
