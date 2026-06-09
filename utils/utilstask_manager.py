import threading
import queue
from utils.site_extractor import SiteExtractor
from utils.system_logger import get_logger

class TaskManager:
    def __init__(self):
        self.queue = queue.Queue()
        self.logger = get_logger("TaskManager")
        self.extractor = SiteExtractor()
        self.running = True
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def add_task(self, url):
        self.queue.put(url)

    def _worker(self):
        while self.running:
            url = self.queue.get()
            try:
                self.logger.info(f"Начало обработки: {url}")
                self.extractor.fetch_text(url)
            except Exception as e:
                self.logger.error(f"Ошибка {url}: {e}")
            finally:
                self.queue.task_done()