import contextlib
import fcntl
from pathlib import Path


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
