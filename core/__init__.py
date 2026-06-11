from core.anti_detect_engine import AntiDetectSession
from core.api_dumper import ApiDumper
from core.api_key_extractor import ApiKeyExtractor, SimpleSiteDownloader
from core.cloudflare_bypass import CloudflareSession
from core.content_capture import SiteContentCapture
from core.design_analyzer import DesignAnalyzer
from core.dynamic_analyzer import DynamicAnalyzer
from core.frontend_cloner import FrontendCloner
from core.paywall_bypass import PaywallBypass
from core.recon_engine import ReconEngine
from core.subdomain_scanner import SubdomainScanner
from core.vuln_scanner import VulnScanner

# Media extraction/downloading lives in utils/ (the upgraded, registry-aware
# implementations): utils.image_processor.ImageExtractor and
# utils.video_processor.VideoDownloader. The earlier core.* copies were
# superseded and removed to kill the duplication.

__all__ = [
    'AntiDetectSession',
    'ApiDumper',
    'ApiKeyExtractor',
    'SimpleSiteDownloader',
    'CloudflareSession',
    'SiteContentCapture',
    'DesignAnalyzer',
    'DynamicAnalyzer',
    'FrontendCloner',
    'PaywallBypass',
    'ReconEngine',
    'SubdomainScanner',
    'VulnScanner',
]
