import re
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional

from utils.browser_utils import SessionBuilder


class ApiKeyExtractor:
    """
    Безопасный инструмент для поиска забытых API-ключей и токенов
    в открытом исходном коде страниц (HTML/JS).
    """

    KEY_PATTERNS = {
        'Generic API Key': r'api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
        'Firebase API Key': r'apiKey\s*:\s*["\']([a-zA-Z0-9_\-]{35,})["\']',
        'Google Cloud / Maps': r'AIzaSy[a-zA-Z0-9_\-]{33}',
        'AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
        'Slack Token': r'xox[bapr]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
    }

    def __init__(self):
        self.target_url: Optional[str] = None
        self.extracted_keys: Dict[str, List[str]] = {}
        self._profile: str = 'chrome_windows'

    def set_profile(self, profile: str):
        self._profile = profile

    def set_target_url(self, url: str):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.target_url = url

    def run_extraction(self) -> Dict:
        result = {
            'targets': [self.target_url],
            'status': 'Not started',
            'keys_found': 0,
            'details': {}
        }

        if not self.target_url:
            result['status'] = 'Error: No URL specified'
            return result

        try:
            session = SessionBuilder(self._profile)
            req = session.make_request(self.target_url)
            opener = session.build_opener()
            with opener.open(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')

            total_found = 0
            for key_type, pattern in self.KEY_PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    unique_matches = list(set(matches))
                    self.extracted_keys[key_type] = unique_matches
                    total_found += len(unique_matches)

            result['status'] = 'Success'
            result['keys_found'] = total_found
            result['details'] = self.extracted_keys
            self._save_report(result)

        except urllib.error.URLError as e:
            result['status'] = f'Network Error: {e.reason}'
        except Exception as e:
            result['status'] = f'Error: {str(e)}'

        return result

    def _save_report(self, result: Dict):
        report_path = Path.home() / "api_keys_report.txt"
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"=== Отчет об анализе сайта {self.target_url} ===\n")
                f.write(f"Статус: {result['status']}\n")
                f.write(f"Найдено потенциальных утечек: {result['keys_found']}\n\n")
                for key_type, keys in self.extracted_keys.items():
                    f.write(f"[{key_type}]:\n")
                    for k in keys:
                        f.write(f"  - {k}\n")
                    f.write("\n")
        except Exception:
            pass


class SimpleSiteDownloader:
    """Безопасный сборщик ссылок и изображений"""

    def __init__(self, target_url: str, profile: str = 'chrome_windows'):
        self.target_url = target_url
        self._profile = profile

    def get_resources(self) -> Dict[str, List[str]]:
        resources = {'links': [], 'images': []}
        try:
            session = SessionBuilder(self._profile)
            req = session.make_request(self.target_url)
            opener = session.build_opener()
            with opener.open(req, timeout=10) as response:
                html = response.read().decode('utf-8', errors='ignore')

            links = re.findall(r'href=["\'](https?://[^"\']+)["\']', html)
            images = re.findall(r'src=["\'](https?://[^"\']+\.(?:png|jpg|jpeg|gif|svg))["\']', html)

            resources['links'] = list(set(links))
            resources['images'] = list(set(images))
        except Exception:
            pass
        return resources
