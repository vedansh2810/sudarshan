"""
DVWA Authentication Helper
Handles DVWA-specific login and session management for Sudarshan scanner
"""

import requests
from bs4 import BeautifulSoup


class DVWAAuth:
    """
    DVWA-specific authentication and session management
    """
    
    @staticmethod
    def login(base_url, username="admin", password="password"):
        """
        Login to DVWA and return authenticated session
        
        Args:
            base_url: DVWA base URL (e.g., http://localhost:8888)
            username: DVWA username (default: admin)
            password: DVWA password (default: password)
        
        Returns:
            requests.Session object with valid DVWA authentication, or None if login fails
        """
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Sudarshan-Scanner/1.0 (Security Research)'
        })
        
        base_url = base_url.rstrip('/')
        
        try:
            # Step 1: Get login page to extract CSRF token
            login_url = f"{base_url}/login.php"
            response = session.get(login_url, timeout=10)
            
            if response.status_code != 200:
                print(f"[!] Failed to access DVWA login page: {response.status_code}")
                return None
            
            # Step 2: Extract CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = None
            
            for inp in soup.find_all('input', {'name': 'user_token'}):
                csrf_token = inp.get('value')
                if csrf_token:
                    break
            
            # Step 3: Perform login
            login_data = {
                'username': username,
                'password': password,
                'Login': 'Login'
            }
            
            if csrf_token:
                login_data['user_token'] = csrf_token
            
            response = session.post(login_url, data=login_data, timeout=10, allow_redirects=True)
            
            # Step 4: Verify login successful
            # Successful login redirects away from login.php
            if 'login.php' not in response.url and response.status_code == 200:
                print(f"[+] DVWA authentication successful for {base_url}")
                return session
            else:
                print(f"[!] DVWA authentication failed (stayed on login page)")
                return None
        
        except requests.exceptions.RequestException as e:
            print(f"[!] Error during DVWA authentication: {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected error during DVWA authentication: {e}")
            return None
    
    @staticmethod
    def set_security_level(session, base_url, level='low'):
        """
        Set DVWA security level
        
        Args:
            session: Authenticated requests.Session
            base_url: DVWA base URL
            level: Security level - 'low', 'medium', 'high', or 'impossible'
        
        Returns:
            True if successful, False otherwise
        """
        if level not in ['low', 'medium', 'high', 'impossible']:
            print(f"[!] Invalid security level: {level}")
            return False
        
        base_url = base_url.rstrip('/')
        
        try:
            # Step 1: Get security page
            security_url = f"{base_url}/security.php"
            response = session.get(security_url, timeout=10)
            
            if response.status_code != 200:
                print(f"[!] Failed to access DVWA security page: {response.status_code}")
                return False
            
            # Step 2: Extract CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = None
            
            for inp in soup.find_all('input', {'name': 'user_token'}):
                csrf_token = inp.get('value')
                if csrf_token:
                    break
            
            # Step 3: Set security level
            data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            if csrf_token:
                data['user_token'] = csrf_token
            
            response = session.post(security_url, data=data, timeout=10)
            
            if response.status_code == 200:
                print(f"[+] DVWA security level set to: {level.upper()}")
                return True
            else:
                print(f"[!] Failed to set DVWA security level")
                return False
        
        except requests.exceptions.RequestException as e:
            print(f"[!] Error setting DVWA security level: {e}")
            return False
        except Exception as e:
            print(f"[!] Unexpected error setting DVWA security level: {e}")
            return False
    
    @staticmethod
    def is_dvwa_target(url):
        """
        Check if a URL looks like a DVWA instance.
        First checks URL indicators, then probes the page content.
        
        Args:
            url: Target URL
        
        Returns:
            True if URL appears to be DVWA
        """
        url_lower = url.lower()
        
        # Check for common DVWA indicators in URL
        indicators = [
            'dvwa',
            '/dvwa/',
            'damn-vulnerable-web-app'
        ]
        
        if any(indicator in url_lower for indicator in indicators):
            return True
        
        # Probe the target for DVWA content markers
        try:
            resp = requests.get(url.rstrip('/') + '/login.php', timeout=5, verify=False,
                              allow_redirects=True)
            if resp.status_code == 200:
                content = resp.text.lower()
                dvwa_markers = [
                    'damn vulnerable web application',
                    'dvwa',
                    'dvwa/images',
                    'dvwa security'
                ]
                if any(marker in content for marker in dvwa_markers):
                    return True
        except Exception:
            pass
        
        return False

