import contextlib
import fcntl
from pathlib import Path


GPG_AGENT_LOCK_FILENAME = '.gpg-agent'


@contextlib.contextmanager
def exclusive_lock(path: str, filename: str):
    locks_dir = Path(path)
    locks_dir.mkdir(exist_ok=True, parents=True)
    with Path(locks_dir, filename).open('w+') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(file, fcntl.LOCK_UN)


@contextlib.contextmanager
def shared_lock(path: str, filename: str):
    locks_dir = Path(path)
    locks_dir.mkdir(exist_ok=True, parents=True)
    with Path(locks_dir, filename).open('w+') as file:
        fcntl.flock(file, fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(file, fcntl.LOCK_UN)
