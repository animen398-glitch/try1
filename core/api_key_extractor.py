import urllib.error
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.paths import get_path_manager
from core.secret_scanner import SecretScanner
from utils.browser_utils import SessionBuilder
from utils.http_retry import urlopen_text


class ApiKeyExtractor:
    """
    Безопасный инструмент для поиска забытых API-ключей и токенов
    в открытом исходном коде страниц (HTML/JS).

    Детектирование делегировано общему core.secret_scanner.SecretScanner —
    единому набору правил для всего приложения.
    """

    def __init__(self):
        self._scanner = SecretScanner()
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
            req = SessionBuilder(self._profile).make_request(self.target_url)
            # gzip-aware fetch with retry — SessionBuilder advertises gzip, so a
            # raw .read() would feed compressed bytes to the regexes.
            content = urlopen_text(req, 10)

            total_found = 0
            for finding in self._scanner.scan_text(content, self.target_url):
                bucket = self.extracted_keys.setdefault(finding['type'], [])
                if finding['match'] not in bucket:
                    bucket.append(finding['match'])
                    total_found += 1

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
        # Write under the PathManager reports/ tree (per-host filename), not the
        # user's home dir, so it lands with the rest of the app's output and a
        # frozen .exe writes to %APPDATA% instead of next to the binary.
        netloc = urlparse(self.target_url or '').netloc.replace(':', '_') or 'site'
        report_path = get_path_manager().get_reports_path(f'api_keys_{netloc}.txt')
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
