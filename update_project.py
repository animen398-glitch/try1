#!/usr/bin/env python3
"""Автоматический пуш обновлений в Git репозиторий"""
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PROJECT_DIR = str(Path(__file__).parent)


def run_git(*args) -> tuple:
    result = subprocess.run(
        ['git', *args],
        capture_output=True,
        text=True,
        cwd=PROJECT_DIR
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def push_updates(commit_message: str = None) -> bool:
    if not commit_message:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M')
        commit_message = f"feat: auto-update {ts}"

    print("[Git] Добавление файлов...")
    code, _, err = run_git('add', '.')
    if code != 0:
        print(f"[Git ERROR] add: {err}")
        return False

    print("[Git] Проверка статуса...")
    code, out, _ = run_git('status', '--porcelain')
    if not out:
        print("[Git] Нет изменений для коммита")
        return True

    print(f"[Git] Коммит: {commit_message}")
    code, _, err = run_git('commit', '-m', commit_message)
    if code != 0:
        print(f"[Git ERROR] commit: {err}")
        return False

    print("[Git] Пуш в origin...")
    code, _, err = run_git('push', 'origin', 'HEAD')
    if code != 0:
        print(f"[Git ERROR] push: {err}")
        return False

    print("[Git] Готово!")
    return True


if __name__ == "__main__":
    msg = sys.argv[1] if len(sys.argv) > 1 else None
    sys.exit(0 if push_updates(msg) else 1)
