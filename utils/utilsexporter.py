import json
import csv
from utils.data_viewer import DataViewer

class DataExporter:
    @staticmethod
    def export(filepath, format='json', data_type=None):
        viewer = DataViewer()
        records = viewer.get_by_type(data_type) if data_type else viewer.get_recent_records(limit=1000)
        
        if not records: return False
        
        if format == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(records, f, indent=4, ensure_ascii=False)
        elif format == 'csv':
            keys = records[0].keys()
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(records)
        return True