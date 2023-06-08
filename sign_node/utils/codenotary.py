import typing
from cas_wrapper import CasWrapper

from plumbum import ProcessExecutionError


class Codenotary:

    def __init__(
        self,
        vcn_lc_api_key: str = "",
        vcn_lc_host: str = "",
        vcn_lc_port: int = 443,
        vcn_binary_path: str = "",
    ):
        self.wrapper = CasWrapper(
            vcn_lc_api_key=vcn_lc_api_key,
            vcn_lc_host=vcn_lc_host,
            vcn_lc_port=vcn_lc_port,
            binary_path=vcn_binary_path,
        )

    def verify_artifact(self, package_path: str) -> typing.Union[bool, dict]:
        response = None
        try:
            self.wrapper.ensure_login()
            response = self.wrapper.authenticate(
                package_path,
                return_json=True,
            )
        except ProcessExecutionError:
            return False
        if not response or not response['verified']:
            return False
        return response

    def notarize_artifact(self, package_path, old_meta) -> str:
        metadata = {
            'unsigned_hash': old_meta['hash'],
            **old_meta['metadata'],
        }
        return self.wrapper.notarize(package_path, metadata)

