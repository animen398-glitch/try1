import re
from typing import Dict, Optional


KNOWN_WAF_PATTERNS: Dict[str, list] = {
    'Cloudflare': ['cf-ray', '__cf_bm', 'cf_clearance', 'cloudflare', 'cf-browser-verification'],
    'Akamai': ['akamai-ghost', 'akamaierror', 'x-akamai'],
    'Sucuri': ['sucuri', 'x-sucuri-id'],
    'Incapsula': ['incapsula', 'visid_incap'],
    'AWS WAF': ['x-amzn-requestid', 'awswaf'],
}

CF_INDICATORS = [
    'cf-browser-verification',
    '__cf_bm',
    'cf_clearance',
    'Checking your browser before accessing',
    'cloudflare',
    'Ray ID:',
]


def detect_cloudflare(html: str, headers: Optional[dict] = None) -> bool:
    """Проверяет признаки защиты Cloudflare в HTML и заголовках ответа"""
    lower = html.lower()
    for indicator in CF_INDICATORS:
        if indicator.lower() in lower:
            return True
    if headers:
        header_str = ' '.join(str(k) + ' ' + str(v) for k, v in headers.items()).lower()
        if 'cf-ray' in header_str or 'cf-cache-status' in header_str:
            return True
    return False


def detect_waf(html: str, headers: Optional[dict] = None) -> Optional[str]:
    """Определяет тип WAF по характерным признакам"""
    combined = html.lower()
    if headers:
        combined += ' ' + ' '.join(str(v).lower() for v in headers.values())

    for waf_name, patterns in KNOWN_WAF_PATTERNS.items():
        if any(p.lower() in combined for p in patterns):
            return waf_name
    return None


def is_rate_limited(status_code: int, html: str) -> bool:
    """Проверяет признаки rate limiting"""
    if status_code in (429, 503):
        return True
    phrases = ['too many requests', 'rate limit', 'slow down']
    return any(p in html.lower() for p in phrases)


def extract_cf_ray(html: str) -> Optional[str]:
    """Извлекает Cloudflare Ray ID для диагностики"""
    match = re.search(r'Ray ID:\s*([a-f0-9]+)', html, re.IGNORECASE)
    return match.group(1) if match else None
