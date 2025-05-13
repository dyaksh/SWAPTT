#!/usr/bin/env python3
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

class SimpleWebCrawler:
    def __init__(self, base_url, max_pages=5, timeout=3):
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url
        
        self.base_url = base_url
        self.target_domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.found_emails = set()
        self.to_visit = [base_url]
        self.headers = {'User-Agent': 'Mozilla/5.0'}

    def extract_emails(self, text):
        return re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)

    def crawl(self):
        print(f"[+] Starting quick crawl on {self.base_url}")
        pages_crawled = 0

        while self.to_visit and pages_crawled < self.max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue

            try:
                resp = requests.get(url, timeout=self.timeout, headers=self.headers)
                if "text/html" not in resp.headers.get('Content-Type', ''):
                    continue

                pages_crawled += 1
                self.visited.add(url)

                # Extract emails
                emails = self.extract_emails(resp.text)
                for email in emails:
                    self.found_emails.add(email)

                # Find more links
                soup = BeautifulSoup(resp.text, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    link = urljoin(url, a_tag['href'])
                    if urlparse(link).netloc == self.target_domain and link not in self.visited:
                        self.to_visit.append(link)

            except Exception as e:
                continue

        self.print_summary()

    def print_summary(self):
        print("\n[+] Crawl Summary")
        print(f"  - Pages Crawled: {len(self.visited)}")
        print(f"  - Emails Found : {len(self.found_emails)}")
        for email in self.found_emails:
            print(f"    * {email}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python simple_crawler.py <url>")
        sys.exit(1)

    target = sys.argv[1]
    crawler = SimpleWebCrawler(target)
    crawler.crawl()
