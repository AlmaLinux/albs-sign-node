from cas_wrapper import CasWrapper

from plumbum import ProcessExecutionError


class Codenotary:

    def __init__(self, api_key, signer_id):
        self.wrapper = CasWrapper(
            cas_api_key=api_key,
            cas_signer_id=signer_id,
        )

    def verify_artifact(self, package_path: str) -> dict:
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