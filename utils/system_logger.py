import logging

from core.paths import get_path_manager


def _log_file() -> str:
    """Absolute path to the system log under the writable data root.

    Resolved through PathManager (not a hardcoded ``data/system.log`` relative
    to the CWD) so a frozen .exe logs under %APPDATA% instead of next to the
    executable / the ephemeral _MEIPASS dir. ``get_db_path`` also ensures the
    parent ``data/`` directory exists.
    """
    return str(get_path_manager().get_db_path('system.log'))


def get_logger(name):
    log_file = _log_file()
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.FileHandler(log_file, encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def get_last_logs(limit=50):
    import os
    log_file = _log_file()
    if not os.path.exists(log_file):
        return []
    with open(log_file, 'r', encoding='utf-8') as f:
        return f.readlines()[-limit:]
