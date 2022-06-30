from cas_wrapper import CasWrapper


class Codenotary:

    def __init__(self, api_key, signer_id):
        self.wrapper = CasWrapper(
            cas_api_key=api_key,
            cas_signer_id=signer_id,
        )

    def verify_artifact(self, package_path: str) -> dict:
        response = self.wrapper.authenticate_artifact(
            package_path, return_json=True
        )
        if not response['verified']:
            return False
        return response

    def notarize_artifact(self, package_path, old_meta) -> str:
        metadata = {
            'unsigned_hash': old_meta['hash'],
            **old_meta['metadata'],
        }
        return self.wrapper.notarize(package_path, metadata)