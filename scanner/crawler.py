import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url, depth=1):
        self.base_url = base_url
        self.depth = depth
        self.visited_urls = set()
        self.found_forms = []
        self.target_links = set()

    def get_links(self, url):
        """Extracts all links from a page that belong to the same domain."""
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            links = []
            for a_tag in soup.find_all("a", href=True):
                link = urljoin(url, a_tag["href"])
                # Only follow links within the same domain
                if urlparse(self.base_url).netloc == urlparse(link).netloc:
                    links.append(link)
            return links
        except Exception as e:
            print(f"Error fetching links from {url}: {e}")
            return []

    def extract_forms(self, url):
        """Extracts all forms and their details from a page."""
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            forms = soup.find_all("form")
            form_details = []
            for form in forms:
                action = form.get("action")
                method = form.get("method", "get").lower()
                inputs = []
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    input_type = input_tag.get("type", "text")
                    input_name = input_tag.get("name")
                    inputs.append({"type": input_type, "name": input_name})
                
                form_details.append({
                    "url": url,
                    "action": action,
                    "method": method,
                    "inputs": inputs
                })
            return form_details
        except Exception as e:
            print(f"Error extracting forms from {url}: {e}")
            return []

    def crawl(self):
        """Main crawl loop based on depth."""
        to_visit = [(self.base_url, 0)]
        
        while to_visit:
            current_url, current_depth = to_visit.pop(0)
            
            if current_url in self.visited_urls or current_depth > self.depth:
                continue
                
            print(f"[*] Crawling: {current_url}")
            self.visited_urls.add(current_url)
            
            # Extract forms from current page
            forms = self.extract_forms(current_url)
            self.found_forms.extend(forms)
            
            # Find new links if depth allows
            if current_depth < self.depth:
                links = self.get_links(current_url)
                for link in links:
                    if link not in self.visited_urls:
                        to_visit.append((link, current_depth + 1))
                        self.target_links.add(link)
        
        return {
            "visited_urls": list(self.visited_urls),
            "forms": self.found_forms
        }
