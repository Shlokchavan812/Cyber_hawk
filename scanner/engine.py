from .crawler import Crawler
from .vuln_scanner import VulnScanner

class ScanEngine:
    def __init__(self, target_url, depth=1):
        self.target_url = target_url
        self.depth = depth
        self.crawler = Crawler(target_url, depth)
        self.scanner = VulnScanner()
        self.results = []

    def run(self):
        """Runs the full scan: Crawl -> Scan."""
        print(f"[*] Starting scan for {self.target_url} with depth {self.depth}")
        
        # 1. Crawl
        crawl_results = self.crawler.crawl()
        visited_urls = crawl_results["visited_urls"]
        forms = crawl_results["forms"]
        
        # 2. Scan URLs for headers and SSL
        for url in visited_urls:
            self.results.extend(self.scanner.check_security_headers(url))
            self.results.extend(self.scanner.check_ssl(url))
            
        # 3. Scan Forms for SQLi and XSS
        for form in forms:
            self.results.extend(self.scanner.test_sqli(form))
            self.results.extend(self.scanner.test_xss(form))
            
        # Remove duplicates (some scans might return same finding)
        unique_results = []
        seen = set()
        for res in self.results:
            # Create a unique key for the finding
            key = (res["url"], res["type"], res.get("vulnerability", ""), res.get("payload", ""))
            if key not in seen:
                unique_results.append(res)
                seen.add(key)
                
        return unique_results
