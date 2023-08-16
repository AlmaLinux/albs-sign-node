from typing import Optional

from immudb_wrapper import ImmudbWrapper
from plumbum import ProcessExecutionError


class Codenotary:
    def __init__(
        self,
        immudb_username: Optional[str] = None,
        immudb_password: Optional[str] = None,
        immudb_database: Optional[str] = None,
        immudb_address: Optional[str] = None,
        immudb_public_key_file: Optional[str] = None,
    ):
        self.wrapper = ImmudbWrapper(
            username=immudb_username,
            password=immudb_password,
            database=immudb_database,
            immudb_address=immudb_address,
            public_key_file=immudb_public_key_file,
        )

    def verify_artifact(self, package_path: str) -> dict:
        result = self.wrapper.authenticate_file(package_path)
        return result

    def notarize_artifact(self, package_path, old_meta) -> Optional[str]:
        metadata = {
            'unsigned_hash': old_meta.get('value', {}).get('Hash'),
            **old_meta.get('value', {}).get('Metadata', {}),
        }
        result = self.wrapper.notarize_file(package_path, metadata)
        return result.get('value', {}).get('Hash')
