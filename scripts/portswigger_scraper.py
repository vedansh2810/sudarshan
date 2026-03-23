#!/usr/bin/env python3
"""
PortSwigger Web Security Academy Scraper
=========================================

Scrapes the PortSwigger Web Security Academy to extract:
  - Lab descriptions and solution steps
  - Security payloads (code examples)
  - HTTP request examples
  - Difficulty levels and categories

Strategy:
  1. Scrape the all-labs page to get every lab URL, title, difficulty, category
  2. Scrape each individual lab page for solutions, payloads, HTTP examples
  3. Also scrape category index pages for category descriptions

Usage:
    python scripts/portswigger_scraper.py

Output:
    data/portswigger_knowledge/portswigger_knowledge.json
    data/portswigger_knowledge/payloads_by_category.json
"""

import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class PortSwiggerScraper:
    """
    Scraper for PortSwigger Web Security Academy.

    Attributes:
        BASE_URL: Base URL for PortSwigger Academy
        ALL_LABS_URL: URL for the all-labs listing page
        CATEGORIES: List of all vulnerability category slugs
        knowledge_base: Dict storing all scraped data
        session: Requests session with browser-like headers
    """

    BASE_URL = "https://portswigger.net/web-security"
    ALL_LABS_URL = "https://portswigger.net/web-security/all-labs"

    # Category slugs as they appear in the all-labs page <h2> ids
    # These match the actual h2 id values from portswigger.net/web-security/all-labs
    CATEGORIES = [
        "sql-injection",
        "cross-site-scripting",
        "cross-site-request-forgery-csrf",
        "clickjacking",
        "dom-based-vulnerabilities",
        "cross-origin-resource-sharing-cors",
        "xml-external-entity-xxe-injection",
        "server-side-request-forgery-ssrf",
        "http-request-smuggling",
        "os-command-injection",
        "server-side-template-injection",
        "path-traversal",
        "access-control-vulnerabilities",
        "authentication",
        "websockets",
        "web-cache-poisoning",
        "insecure-deserialization",
        "information-disclosure",
        "business-logic-vulnerabilities",
        "http-host-header-attacks",
        "oauth-authentication",
        "file-upload-vulnerabilities",
        "jwt",
        "essential-skills",
        "prototype-pollution",
        "graphql-api-vulnerabilities",
        "race-conditions",
        "nosql-injection",
        "api-testing",
        "web-llm-attacks",
        "web-cache-deception",
    ]

    # Friendly display names
    CATEGORY_DISPLAY = {
        "sql-injection": "SQL Injection",
        "cross-site-scripting": "Cross-Site Scripting (XSS)",
        "cross-site-request-forgery-csrf": "Cross-Site Request Forgery (CSRF)",
        "clickjacking": "Clickjacking",
        "dom-based-vulnerabilities": "DOM-based Vulnerabilities",
        "cross-origin-resource-sharing-cors": "Cross-Origin Resource Sharing (CORS)",
        "xml-external-entity-xxe-injection": "XML External Entity (XXE) Injection",
        "server-side-request-forgery-ssrf": "Server-Side Request Forgery (SSRF)",
        "http-request-smuggling": "HTTP Request Smuggling",
        "os-command-injection": "OS Command Injection",
        "server-side-template-injection": "Server-Side Template Injection (SSTI)",
        "path-traversal": "Directory/Path Traversal",
        "access-control-vulnerabilities": "Access Control Vulnerabilities",
        "authentication": "Authentication Vulnerabilities",
        "websockets": "WebSockets",
        "web-cache-poisoning": "Web Cache Poisoning",
        "insecure-deserialization": "Insecure Deserialization",
        "information-disclosure": "Information Disclosure",
        "business-logic-vulnerabilities": "Business Logic Vulnerabilities",
        "http-host-header-attacks": "HTTP Host Header Attacks",
        "oauth-authentication": "OAuth Authentication",
        "file-upload-vulnerabilities": "File Upload Vulnerabilities",
        "jwt": "JWT Attacks",
        "essential-skills": "Essential Skills",
        "prototype-pollution": "Prototype Pollution",
        "graphql-api-vulnerabilities": "GraphQL API Vulnerabilities",
        "race-conditions": "Race Conditions",
        "nosql-injection": "NoSQL Injection",
        "api-testing": "API Testing",
        "web-llm-attacks": "Web LLM Attacks",
        "web-cache-deception": "Web Cache Deception",
    }

    def __init__(self):
        """Initialize the scraper with session and knowledge base."""
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })

        self.knowledge_base = {
            "categories": {},
            "labs": [],
            "payloads": {},
            "scraped_at": None,
        }

        # Tracking
        self._seen_lab_urls = set()

    # ------------------------------------------------------------------
    # Step 1: Discover all labs from the all-labs page
    # ------------------------------------------------------------------

    def discover_all_labs(self):
        """
        Load the pre-extracted lab index from lab_index.json.

        The all-labs page loads lab data via JavaScript widgets, so we
        cannot scrape it with requests alone. Instead we use a pre-extracted
        index created by scripts/extract_lab_index.py (which uses Playwright).

        If lab_index.json does not exist, prints instructions to create it.

        Returns:
            dict mapping category_slug -> list of lab info dicts
        """
        index_path = os.path.join("data", "portswigger_knowledge", "lab_index.json")

        if not os.path.exists(index_path):
            print(f"[!] Lab index not found at: {index_path}")
            print(f"[!] The PortSwigger all-labs page loads labs via JavaScript.")
            print(f"[!] Run the extraction script first:")
            print(f"        python scripts/extract_lab_index.py")
            print(f"[!] This requires Playwright: pip install playwright && playwright install chromium")
            return {}

        print(f"[*] Loading lab index from: {index_path}")
        with open(index_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        labs_list = data.get("labs", [])
        labs_by_category = {}

        for lab in labs_list:
            category = lab.get("category", "uncategorized")
            url = lab.get("url", "")
            title = lab.get("title", "")
            difficulty = lab.get("difficulty", "unknown")

            if not url or not title:
                continue

            if url in self._seen_lab_urls:
                continue
            self._seen_lab_urls.add(url)

            if category not in labs_by_category:
                labs_by_category[category] = []

            labs_by_category[category].append({
                "title": title,
                "url": url,
                "difficulty": difficulty,
            })

        # Print summary
        total = sum(len(v) for v in labs_by_category.values())
        print(f"    [+] Total unique labs loaded: {total}")
        for cat, labs in sorted(labs_by_category.items(), key=lambda x: -len(x[1])):
            display = self.CATEGORY_DISPLAY.get(cat, cat)
            print(f"        {display}: {len(labs)} labs")

        return labs_by_category

    def _category_from_url(self, url):
        """
        Infer category from a lab URL path.

        Examples:
            /web-security/sql-injection/lab-retrieve-hidden-data -> sql-injection
            /web-security/sql-injection/union-attacks/lab-... -> sql-injection
        """
        path = url.replace("https://portswigger.net/web-security/", "")
        parts = path.split("/")
        if len(parts) >= 2:
            candidate = parts[0]
            if candidate in self.CATEGORIES:
                return candidate
            return candidate
        return "uncategorized"

    # ------------------------------------------------------------------
    # Step 2: Scrape category description pages
    # ------------------------------------------------------------------

    def scrape_category_description(self, category, delay=2):
        """
        Scrape a category's main page for its description text.

        Args:
            category: Category slug
            delay: Rate limiting delay

        Returns:
            str: Category description
        """
        # Category URL mapping: the h2 id doesn't always match the URL path
        # e.g. h2 id "xml-external-entity-xxe-injection" -> URL path "xxe"
        CATEGORY_URL_MAP = {
            "xml-external-entity-xxe-injection": "xxe",
            "server-side-request-forgery-ssrf": "ssrf",
            "http-request-smuggling": "request-smuggling",
            "cross-origin-resource-sharing-cors": "cors",
            "dom-based-vulnerabilities": "dom-based",
            "access-control-vulnerabilities": "access-control",
            "http-host-header-attacks": "host-header",
            "oauth-authentication": "oauth",
            "file-upload-vulnerabilities": "file-upload",
            "graphql-api-vulnerabilities": "graphql",
            "web-llm-attacks": "llm-attacks",
            "web-cache-deception": "web-cache-deception",
        }
        url_slug = CATEGORY_URL_MAP.get(category, category)
        url = f"{self.BASE_URL}/{url_slug}"
        try:
            time.sleep(delay)
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"    [!] Error fetching {category} description: {exc}")
            return ""

        soup = BeautifulSoup(resp.text, "html.parser")
        main_content = soup.find("main") or soup.find("div", id="main-content") or soup
        paragraphs = main_content.find_all("p")
        desc_parts = []
        for p in paragraphs[:5]:
            text = p.get_text(strip=True)
            if text and len(text) > 20:
                desc_parts.append(text)
                if len(" ".join(desc_parts)) > 500:
                    break
        return " ".join(desc_parts)[:1000]

    # ------------------------------------------------------------------
    # Step 3: Scrape individual lab pages
    # ------------------------------------------------------------------

    def scrape_lab_solution(self, lab_url, lab_title, category):
        """
        Scrape an individual lab page for solution, payloads, and examples.

        Args:
            lab_url: Full URL of the lab page
            lab_title: Title of the lab
            category: Category slug

        Returns:
            dict with keys: title, url, category, difficulty, description,
                            solution_steps, payloads, http_examples
        """
        result = {
            "title": lab_title,
            "url": lab_url,
            "category": category,
            "difficulty": "unknown",
            "description": "",
            "solution_steps": [],
            "payloads": [],
            "http_examples": [],
        }

        try:
            resp = self.session.get(lab_url, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            print(f"        [!] Error fetching lab {lab_url}: {exc}")
            return result

        soup = BeautifulSoup(resp.text, "html.parser")

        # --- Find the main content section ---
        # PortSwigger lab pages use <div class="section theme-white"> inside <main>
        content_section = (
            soup.find("div", class_="section")
            or soup.find("main")
            or soup
        )

        # --- Difficulty ---
        page_text_lower = resp.text[:5000].lower()
        if "apprentice" in page_text_lower:
            result["difficulty"] = "apprentice"
        elif "practitioner" in page_text_lower:
            result["difficulty"] = "practitioner"
        elif "expert" in page_text_lower:
            result["difficulty"] = "expert"

        # --- Description ---
        # Paragraphs follow the <h1> as siblings inside the section div
        h1 = content_section.find("h1")
        desc_parts = []
        if h1:
            current = h1.find_next_sibling()
            while current:
                tag_name = getattr(current, "name", None)
                # Stop at solution divs or other major sections
                if tag_name == "div" and current.get("class"):
                    classes = current.get("class", [])
                    if "component-solution" in classes or "expandable-container" in classes:
                        break
                if tag_name == "p":
                    text = current.get_text(strip=True)
                    if text and len(text) > 10:
                        desc_parts.append(text)
                        if len(" ".join(desc_parts)) > 500:
                            break
                elif tag_name == "code":
                    # Inline code blocks that are part of the description
                    code_text = current.get_text(strip=True)
                    if code_text:
                        desc_parts.append(f"[Code: {code_text}]")
                current = current.find_next_sibling()

        # Fallback: search for paragraphs in the content section
        if not desc_parts:
            for p in content_section.find_all("p"):
                text = p.get_text(strip=True)
                if text and len(text) > 20:
                    desc_parts.append(text)
                    if len(" ".join(desc_parts)) > 500:
                        break

        result["description"] = " ".join(desc_parts)[:1000]

        # --- Solution Steps ---
        result["solution_steps"] = self._extract_solution_steps(content_section)

        # --- Code Payloads ---
        result["payloads"] = self._extract_payloads(content_section)

        # --- HTTP Examples ---
        result["http_examples"] = self._extract_http_examples(content_section)

        return result

    def _extract_solution_steps(self, content_section):
        """
        Extract solution steps from the lab page.

        PortSwigger uses <div class="component-solution expandable-container">
        containing a <summary> with "Solution" and a <div class="content">
        with the actual steps (paragraphs, lists, code blocks).
        """
        steps = []

        # Strategy 1: Find the component-solution expandable container
        solution_containers = content_section.find_all(
            "div", class_="component-solution"
        )
        for container in solution_containers:
            # Check if this is the "Solution" container (not "Community solutions")
            summary = container.find("summary")
            if summary:
                summary_text = summary.get_text(strip=True).lower()
                if "community" in summary_text:
                    continue

            # Find the .content div inside
            content_div = container.find("div", class_="content")
            if content_div:
                for elem in content_div.find_all(["p", "li", "code", "pre"]):
                    tag = elem.name
                    text = elem.get_text(strip=True)
                    if not text or len(text) < 3:
                        continue
                    if text in steps:
                        continue
                    # Skip nested li items already captured in parent
                    if tag == "li" and elem.find_parent("li"):
                        continue
                    steps.append(text)

            if steps:
                return steps

        # Strategy 2: Find h4 "Solution" and walk through content
        solution_header = None
        for header in content_section.find_all(["h4", "h3", "h2"]):
            header_text = header.get_text(strip=True).lower()
            if header_text == "solution":
                solution_header = header
                break

        if solution_header:
            # The solution header is in a <summary> tag; the content is
            # in a sibling or parent's other child elements
            parent = solution_header.find_parent()
            if parent:
                # Look for content in the parent's siblings or parent's parent
                container = parent.find_parent()
                if container:
                    content_div = container.find("div", class_="content")
                    if content_div:
                        for elem in content_div.find_all(["p", "li", "pre", "code"]):
                            text = elem.get_text(strip=True)
                            if text and len(text) > 3 and text not in steps:
                                steps.append(text)
                    if steps:
                        return steps

        # Strategy 3: Collect from ordered lists
        for ol in content_section.find_all("ol"):
            for li in ol.find_all("li", recursive=False):
                text = li.get_text(strip=True)
                if text and len(text) > 10 and text not in steps:
                    steps.append(text)

        return steps

    def _extract_payloads(self, soup):
        """
        Extract code payloads from <code> and <pre> elements.

        Returns:
            list of dicts: [{'code': str, 'context': str}, ...]
        """
        payloads = []
        seen_codes = set()

        # From <code> elements
        for code_block in soup.find_all("code"):
            code_text = code_block.get_text(strip=True)
            if not code_text or len(code_text) < 3:
                continue
            if code_text in seen_codes:
                continue
            seen_codes.add(code_text)

            context = ""
            parent_p = code_block.find_parent("p")
            if parent_p:
                context = parent_p.get_text(strip=True)[:200]
            else:
                parent_li = code_block.find_parent("li")
                if parent_li:
                    context = parent_li.get_text(strip=True)[:200]

            payloads.append({"code": code_text, "context": context})

        # From <pre> blocks without <code> children
        for pre_block in soup.find_all("pre"):
            if pre_block.find("code"):
                continue
            pre_text = pre_block.get_text(strip=True)
            if not pre_text or len(pre_text) < 5:
                continue
            if pre_text in seen_codes:
                continue
            seen_codes.add(pre_text)

            context = ""
            parent_p = pre_block.find_parent("p")
            if parent_p:
                context = parent_p.get_text(strip=True)[:200]

            payloads.append({"code": pre_text, "context": context})

        return payloads

    def _extract_http_examples(self, soup):
        """
        Extract HTTP request/response examples from <pre> and <code> elements.

        PortSwigger labs use <code> blocks (not <pre>) for HTTP examples.

        Returns:
            list of HTTP example strings
        """
        examples = []
        http_pattern = re.compile(
            r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP/)\s",
            re.IGNORECASE,
        )
        http_header_markers = [
            "Content-Type:", "Host:", "Cookie:", "Transfer-Encoding:",
            "Content-Length:", "Connection:", "User-Agent:",
        ]

        for block in soup.find_all(["pre", "code"]):
            text = block.get_text(strip=True)
            if not text or len(text) < 10:
                continue

            is_http = http_pattern.search(text)
            if not is_http:
                # Check for HTTP header markers
                is_http = any(marker in text for marker in http_header_markers)

            if is_http and text not in examples:
                examples.append(text)

        return examples

    # ------------------------------------------------------------------
    # Main orchestrator
    # ------------------------------------------------------------------

    def scrape_all(self, delay=2):
        """
        Scrape all categories and their labs.

        1. Discover all labs from the all-labs page
        2. Scrape category description pages
        3. Scrape each individual lab solution page

        Args:
            delay: Seconds to wait between HTTP requests (default: 2)
        """
        print("=" * 70)
        print("PortSwigger Web Security Academy Scraper")
        print("=" * 70)
        print(f"Rate limit delay: {delay}s")
        print()

        # --- Step 1: Discover all labs ---
        labs_by_category = self.discover_all_labs()

        if not labs_by_category:
            print("[!] No labs discovered. Aborting.")
            return

        all_categories = sorted(labs_by_category.keys())
        total_labs = sum(len(v) for v in labs_by_category.values())
        print(f"\n[*] Categories found: {len(all_categories)}")
        print(f"[*] Total labs to scrape: {total_labs}")
        print()

        # --- Step 2: Scrape category descriptions ---
        print("[*] Fetching category descriptions...")
        for category in all_categories:
            display = self.CATEGORY_DISPLAY.get(category, category)
            print(f"    Fetching description for: {display}")
            desc = self.scrape_category_description(category, delay=delay)
            self.knowledge_base["categories"][category] = {
                "display_name": display,
                "description": desc,
                "total_labs": len(labs_by_category.get(category, [])),
            }
        print()

        # --- Step 3: Scrape each lab ---
        labs_scraped = 0
        for cat_idx, category in enumerate(all_categories, 1):
            display = self.CATEGORY_DISPLAY.get(category, category)
            cat_labs = labs_by_category[category]
            print(f"[*] [{cat_idx}/{len(all_categories)}] "
                  f"Category: {display} ({len(cat_labs)} labs)")

            if category not in self.knowledge_base["payloads"]:
                self.knowledge_base["payloads"][category] = []

            for lab_idx, lab_info in enumerate(cat_labs, 1):
                print(f"    [{lab_idx}/{len(cat_labs)}] "
                      f"{lab_info['title'][:65]}...")

                time.sleep(delay)
                lab_data = self.scrape_lab_solution(
                    lab_info["url"], lab_info["title"], category
                )

                # Use difficulty from all-labs page if lab page didn't detect it
                if lab_data["difficulty"] == "unknown" and lab_info.get("difficulty", "unknown") != "unknown":
                    lab_data["difficulty"] = lab_info["difficulty"]

                self.knowledge_base["labs"].append(lab_data)

                # Collect payloads for the category
                for payload in lab_data["payloads"]:
                    self.knowledge_base["payloads"][category].append({
                        "payload": payload["code"],
                        "context": payload["context"],
                        "difficulty": lab_data["difficulty"],
                        "lab_title": lab_data["title"],
                    })

                pc = len(lab_data["payloads"])
                sc = len(lab_data["solution_steps"])
                hc = len(lab_data["http_examples"])
                print(f"        [+] {pc} payloads, {sc} steps, {hc} HTTP examples")

                labs_scraped += 1

            print()

        self.knowledge_base["scraped_at"] = datetime.utcnow().isoformat()
        print(f"[+] Finished. Total labs scraped: {labs_scraped}")

    def resume_from_category(self, start_category, delay=2):
        """
        Resume scraping from a specific category.

        Useful when scraping was interrupted midway.

        Args:
            start_category: Category slug to resume from
            delay: Seconds between requests
        """
        print(f"[*] Discovering all labs first...")
        labs_by_category = self.discover_all_labs()
        all_cats = sorted(labs_by_category.keys())

        if start_category not in all_cats:
            print(f"[!] Category '{start_category}' not found.")
            print(f"    Available: {', '.join(all_cats)}")
            return

        start_idx = all_cats.index(start_category)
        remaining = all_cats[start_idx:]
        print(f"[*] Resuming from '{start_category}' "
              f"({len(remaining)} categories remaining)")

        labs_scraped = 0
        for cat_idx, category in enumerate(remaining, 1):
            display = self.CATEGORY_DISPLAY.get(category, category)
            cat_labs = labs_by_category.get(category, [])
            print(f"\n[*] [{cat_idx}/{len(remaining)}] "
                  f"Category: {display} ({len(cat_labs)} labs)")

            if category not in self.knowledge_base["categories"]:
                desc = self.scrape_category_description(category, delay=delay)
                self.knowledge_base["categories"][category] = {
                    "display_name": display,
                    "description": desc,
                    "total_labs": len(cat_labs),
                }

            if category not in self.knowledge_base["payloads"]:
                self.knowledge_base["payloads"][category] = []

            for lab_idx, lab_info in enumerate(cat_labs, 1):
                # Skip already-scraped labs
                if any(l["url"] == lab_info["url"]
                       for l in self.knowledge_base["labs"]):
                    continue

                print(f"    [{lab_idx}/{len(cat_labs)}] "
                      f"{lab_info['title'][:65]}...")
                time.sleep(delay)

                lab_data = self.scrape_lab_solution(
                    lab_info["url"], lab_info["title"], category
                )
                if lab_data["difficulty"] == "unknown" and lab_info.get("difficulty", "unknown") != "unknown":
                    lab_data["difficulty"] = lab_info["difficulty"]

                self.knowledge_base["labs"].append(lab_data)
                for payload in lab_data["payloads"]:
                    self.knowledge_base["payloads"][category].append({
                        "payload": payload["code"],
                        "context": payload["context"],
                        "difficulty": lab_data["difficulty"],
                        "lab_title": lab_data["title"],
                    })

                pc = len(lab_data["payloads"])
                sc = len(lab_data["solution_steps"])
                print(f"        [+] {pc} payloads, {sc} steps")
                labs_scraped += 1

        self.knowledge_base["scraped_at"] = datetime.utcnow().isoformat()
        print(f"\n[+] Resume complete. Labs scraped this session: {labs_scraped}")

    # ------------------------------------------------------------------
    # Save results
    # ------------------------------------------------------------------

    def save(self, output_dir="data/portswigger_knowledge"):
        """
        Save knowledge base to JSON files.

        Creates:
            - portswigger_knowledge.json  (complete data)
            - payloads_by_category.json   (payloads organized by category)
        """
        os.makedirs(output_dir, exist_ok=True)

        # Full knowledge base
        kb_path = os.path.join(output_dir, "portswigger_knowledge.json")
        with open(kb_path, "w", encoding="utf-8") as f:
            json.dump(self.knowledge_base, f, indent=2, ensure_ascii=False)
        size_mb = os.path.getsize(kb_path) / (1024 * 1024)
        print(f"\n[+] Knowledge base saved: {kb_path} ({size_mb:.2f} MB)")

        # Payloads by category
        payloads_path = os.path.join(output_dir, "payloads_by_category.json")
        with open(payloads_path, "w", encoding="utf-8") as f:
            json.dump(
                self.knowledge_base["payloads"], f,
                indent=2, ensure_ascii=False,
            )
        size_mb = os.path.getsize(payloads_path) / (1024 * 1024)
        print(f"[+] Payloads saved: {payloads_path} ({size_mb:.2f} MB)")

    # ------------------------------------------------------------------
    # Summary statistics
    # ------------------------------------------------------------------

    def generate_summary(self):
        """
        Generate and print summary statistics.

        Returns:
            dict with summary data
        """
        labs = self.knowledge_base["labs"]
        payloads = self.knowledge_base["payloads"]
        total_payloads = sum(len(p) for p in payloads.values())
        difficulties = [lab.get("difficulty", "unknown") for lab in labs]
        diff_counts = dict(Counter(difficulties))

        labs_by_cat = {}
        for lab in labs:
            cat = lab["category"]
            labs_by_cat[cat] = labs_by_cat.get(cat, 0) + 1

        payloads_by_cat = {c: len(pl) for c, pl in payloads.items()}

        summary = {
            "total_categories": len(self.knowledge_base["categories"]),
            "total_labs": len(labs),
            "labs_by_difficulty": diff_counts,
            "labs_by_category": labs_by_cat,
            "total_payloads": total_payloads,
            "payloads_by_category": payloads_by_cat,
            "scraped_at": self.knowledge_base.get("scraped_at"),
        }

        print()
        print("=" * 70)
        print("Scraping Complete!")
        print("=" * 70)
        print(f"  Total Categories: {summary['total_categories']}")
        print(f"  Total Labs:       {summary['total_labs']}")
        print(f"  Total Payloads:   {summary['total_payloads']}")
        print()

        print("  Labs by Difficulty:")
        for diff in ("apprentice", "practitioner", "expert", "unknown"):
            if diff in diff_counts:
                print(f"    {diff}: {diff_counts[diff]}")
        print()

        sorted_cats = sorted(labs_by_cat.items(), key=lambda x: x[1], reverse=True)
        print("  Top Categories by Lab Count:")
        for cat, count in sorted_cats[:10]:
            display = self.CATEGORY_DISPLAY.get(cat, cat)
            print(f"    {display}: {count} labs")
        print()

        sorted_payloads = sorted(payloads_by_cat.items(), key=lambda x: x[1], reverse=True)
        print("  Top Categories by Payload Count:")
        for cat, count in sorted_payloads[:10]:
            display = self.CATEGORY_DISPLAY.get(cat, cat)
            print(f"    {display}: {count} payloads")
        print()

        return summary


# ======================================================================
# Entry point
# ======================================================================

def main():
    """Run the full scraper."""
    scraper = PortSwiggerScraper()

    try:
        scraper.scrape_all(delay=2)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Saving partial results...")
    except Exception as exc:
        print(f"\n[!] Unexpected error: {exc}")
        import traceback
        traceback.print_exc()
        print("[*] Saving partial results...")

    scraper.save()
    scraper.generate_summary()


if __name__ == "__main__":
    main()
