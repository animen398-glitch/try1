"""
ApiDumper — saves all captured API endpoint data to structured files.
Input:  dynamic_result dict from DynamicAnalyzer.analyze_dynamic_traffic()
Output: organized directory under output_dir/api_dump_<slug>_<ts>/
"""
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional


def _write(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')


class ApiDumper:
    def __init__(self):
        self._output_dir: Optional[Path] = None

    def configure(self, output_dir: str):
        self._output_dir = Path(output_dir)

    def dump(self, dynamic_result: Dict, url: str = '') -> Dict:
        """
        Persists all intercepted data from a DynamicAnalyzer result to disk.
        Returns {'status', 'output_dir', 'files_written', 'endpoint_count'}.
        """
        if not self._output_dir:
            return {'status': 'Error', 'error': 'output_dir not configured'}

        slug = re.sub(
            r'[^\w.-]', '_',
            url.replace('https://', '').replace('http://', ''),
        )[:40]
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dump_dir = self._output_dir / f'api_dump_{slug}_{stamp}'
        dump_dir.mkdir(parents=True, exist_ok=True)

        files_written = 0
        endpoints = dynamic_result.get('endpoints', [])

        _write(dump_dir / 'summary.json', {
            'url': url,
            'timestamp': stamp,
            'total_endpoints': len(endpoints),
            'unique_hosts': dynamic_result.get('unique_hosts', 0),
            'total_api_calls': dynamic_result.get('total_api_calls', 0),
            'endpoints': endpoints,
        })
        files_written += 1

        json_structs = dynamic_result.get('json_structures', [])
        if json_structs:
            resp_dir = dump_dir / 'json_responses'
            resp_dir.mkdir(exist_ok=True)
            for i, struct in enumerate(json_structs, 1):
                _write(resp_dir / f'response_{i:03d}.json', struct)
                files_written += 1

        secrets = dynamic_result.get('secrets_found', [])
        if secrets:
            _write(dump_dir / 'secrets.json', secrets)
            files_written += 1

        auth = dynamic_result.get('auth_headers', [])
        if auth:
            _write(dump_dir / 'auth_headers.json', auth)
            files_written += 1

        rg = dynamic_result.get('runtime_globals', {})
        if rg:
            _write(dump_dir / 'runtime_globals.json', rg)
            files_written += 1

        _write(dump_dir / 'raw_dynamic_result.json', dynamic_result)
        files_written += 1

        return {
            'status': 'Success',
            'output_dir': str(dump_dir),
            'files_written': files_written,
            'endpoint_count': len(endpoints),
        }
