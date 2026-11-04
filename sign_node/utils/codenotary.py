import threading
from typing import Optional

from immudb_wrapper import ImmudbWrapper


class Codenotary:
    def __init__(
        self,
        immudb_username: Optional[str] = None,
        immudb_password: Optional[str] = None,
        immudb_database: Optional[str] = None,
        immudb_address: Optional[str] = None,
        immudb_public_key_file: Optional[str] = None,
    ):
        self._wrapper_kwargs = {
            'username': immudb_username,
            'password': immudb_password,
            'database': immudb_database,
            'immudb_address': immudb_address,
            'public_key_file': immudb_public_key_file,
        }
        # An immudb client keeps per-connection state (auth stub, last
        # verified server state), so every thread gets its own one
        self._local = threading.local()
        # fail early on bad settings
        self._local.wrapper = ImmudbWrapper(**self._wrapper_kwargs)

    @property
    def wrapper(self) -> ImmudbWrapper:
        if not hasattr(self._local, 'wrapper'):
            self._local.wrapper = ImmudbWrapper(**self._wrapper_kwargs)
        return self._local.wrapper

    def verify_artifact(self, package_path: str) -> dict:
        result = self.wrapper.authenticate_file(package_path)
        if 'error' in result:
            return {}
        return result

    def notarize_artifact(self, package_path, old_meta) -> Optional[str]:
        metadata = {
            'unsigned_hash': old_meta.get('value', {}).get('Hash'),
            **old_meta.get('value', {}).get('Metadata', {}),
        }
        result = self.wrapper.notarize_file(package_path, metadata)
        return result.get('value', {}).get('Hash')
