"""core/_scrapy_spider.py

Standalone Scrapy spider, executed in a *child process* by core.scrapy_crawler.
It is never imported by the GUI: Scrapy embeds the Twisted reactor, which cannot
coexist with Qt's event loop or be restarted in-process, so each crawl gets a
fresh interpreter. ``import scrapy`` therefore happens only here, in the child.

Usage (invoked by ScrapyCrawler, not by hand):

    python core/_scrapy_spider.py <url> --out <file.jsonl> \
        --max-pages 50 --depth 2 [--user-agent UA] [--obey-robots]

Crawls within the start URL's registered domain, bounded by page count and link
depth, and writes one JSON object per visited page to the ``--out`` feed.
"""

import argparse
import sys
from urllib.parse import urlparse


def _build_spider(start_url, allowed_domain):
    from scrapy.linkextractors import LinkExtractor
    from scrapy.spiders import CrawlSpider, Rule

    class SiteSpider(CrawlSpider):
        name = 'site'
        allowed_domains = [allowed_domain] if allowed_domain else []
        start_urls = [start_url]
        rules = (
            Rule(LinkExtractor(allow_domains=allowed_domains),
                 callback='parse_page', follow=True),
        )

        def parse_page(self, response):
            title = ''
            try:
                title = (response.css('title::text').get() or '').strip()
            except Exception:
                pass
            ctype = response.headers.get('Content-Type', b'').decode('latin-1', 'ignore')
            yield {
                'url': response.url,
                'status': response.status,
                'title': title[:200],
                'content_type': ctype.split(';')[0].strip(),
                'depth': response.meta.get('depth', 0),
                'size': len(response.body),
            }

    return SiteSpider


def main(argv=None):
    parser = argparse.ArgumentParser(description='Bounded same-domain Scrapy crawl.')
    parser.add_argument('url')
    parser.add_argument('--out', required=True, help='JSON Lines feed output path')
    parser.add_argument('--max-pages', type=int, default=50)
    parser.add_argument('--depth', type=int, default=2)
    parser.add_argument('--user-agent', default=(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'))
    parser.add_argument('--obey-robots', action='store_true')
    opts = parser.parse_args(argv)

    url = opts.url if opts.url.startswith(('http://', 'https://')) else 'https://' + opts.url
    domain = urlparse(url).netloc

    try:
        from scrapy.crawler import CrawlerProcess
    except ImportError as e:
        sys.stderr.write(f'scrapy unavailable: {e}\n')
        return 3

    process = CrawlerProcess(settings={
        'FEEDS': {opts.out: {'format': 'jsonlines', 'overwrite': True,
                             'encoding': 'utf-8'}},
        'DEPTH_LIMIT': opts.depth,
        'CLOSESPIDER_PAGECOUNT': opts.max_pages,
        'CONCURRENT_REQUESTS': 8,
        'DOWNLOAD_TIMEOUT': 20,
        'ROBOTSTXT_OBEY': opts.obey_robots,
        'USER_AGENT': opts.user_agent,
        'LOG_LEVEL': 'ERROR',
        'TELNETCONSOLE_ENABLED': False,
    })
    process.crawl(_build_spider(url, domain))
    process.start()  # blocks until the crawl finishes
    return 0


if __name__ == '__main__':
    sys.exit(main())
