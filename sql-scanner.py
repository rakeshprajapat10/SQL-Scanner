import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import webbrowser
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

def print_banner():
    # ANSI escape codes for colors
    green_text = "\033[92m"
    reset_color = "\033[0m"
    
    banner_text = """
           _      ____                                  
 ___  __ _| |    / ___|  ___ __ _ _ __  _ __   ___ _ __ 
/ __|/ _` | |____\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
\__ \ (_| | |_____|__) | (_| (_| | | | | | | |  __/ |   
|___/\__, |_|    |____/ \___\__,_|_| |_|_| |_|\___|_|   
        |_|    ~by  rakesh                v1.0                                          
    """

    print(green_text + banner_text + reset_color)

print_banner()

def setup_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Ensure GUI is off
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)
    return driver

def scan_website(url):
    try:
        driver = setup_driver()
        discovered_urls = discover_urls(driver, url)
        driver.quit()
        
        if not discovered_urls:
            print(f"No URLs discovered on {url}.")
            return

        print(f"Discovered {len(discovered_urls)} URLs on {url}:\n")
        for i, discovered_url in enumerate(discovered_urls, start=1):
            print(f"{i}. {discovered_url}")
        for page_url in discovered_urls:
            vulnerabilities = scan_url(page_url)
            if vulnerabilities:
                print(f"\nVulnerabilities found on {page_url}:")
                for vulnerability, attack_method in vulnerabilities.items():
                    print(f"\nVulnerability: {vulnerability}")
                    print(f"Attack Method: {attack_method}")
                    if vulnerability == "SQL injection vulnerability":
                        print("\nSQL Injection Method:")
                        print("1. Identify the input field vulnerable to SQL injection")
                        print("2. Inject SQL code to manipulate the query, e.g., ' OR '1'='1'")
                        print("3. Observe the response for any error messages or unusual behavior")
                        exploit_sql_injection(page_url)

                    if vulnerability == "Cross-site scripting (XSS) vulnerability":
                        print("\nXSS Attack Method:")
                        print("1. Identify the input field vulnerable to XSS")
                        print("2. Inject malicious scripts, e.g., <script>alert('XSS')</script>")
                        print("3. Observe the behavior of the injected script")
                        exploit_xss_vulnerability(page_url)
            else:
                print(f"No vulnerabilities found on {page_url}.")

    except Exception as e:
        print(f"An error occurred while scanning the website: {e}")

def discover_urls(driver, url):
    discovered_urls = []
    try:
        driver.get(url)
        soup = BeautifulSoup(driver.page_source, "html.parser")
        for anchor_tag in soup.find_all("a"):
            href = anchor_tag.get("href")
            if href:
                absolute_url = urljoin(url, href)
                discovered_urls.append(absolute_url)
    except Exception as e:
        print(f"Error discovering URLs on {url}: {e}")
    return discovered_urls

def scan_url(url):
    vulnerabilities = {}

    try:
        if is_sql_injection_vulnerable(url):
            vulnerabilities["SQL injection vulnerability"] = "Injecting SQL code into input fields"
        if is_xss_vulnerable(url):
            vulnerabilities["Cross-site scripting (XSS) vulnerability"] = "Injecting malicious scripts into input fields"
        if has_insecure_configuration(url):
            vulnerabilities["Insecure server configuration"] = "Exploiting insecure communication protocols"
    except Exception as e:
        print(f"Error scanning {url}: {e}")
    return vulnerabilities

def is_sql_injection_vulnerable(url):
    try:
        payload = "' OR '1'='1"
        response = requests.get(url + "?id=" + payload, verify=False)  # Bypass SSL verification
        if re.search(r"error|warning", response.text, re.IGNORECASE):
            return True
    except requests.RequestException as e:
        print(f"Error checking SQL injection vulnerability on {url}: {e}")
    return False

def is_xss_vulnerable(url):
    try:
        payload = "<script>alert('XSS')</script>"
        response = requests.get(url + "?input=" + payload, verify=False)  # Bypass SSL verification
        if payload in response.text:
            return True
    except requests.RequestException as e:
        print(f"Error checking XSS vulnerability on {url}: {e}")
    return False

def has_insecure_configuration(url):
    if not url.startswith("https"):
        return True
    return False

def exploit_sql_injection(url):
    webbrowser.open(url)

def exploit_xss_vulnerability(url):
    webbrowser.open(url)

if __name__ == "__main__":
    url = input("Enter URL: ").strip()
    if not url.startswith("http"):
        url = "http://" + url
    scan_website(url)
