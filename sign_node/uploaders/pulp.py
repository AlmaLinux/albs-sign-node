import logging
import os
import time
import typing
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from pulpcore.client.pulp_rpm import ApiClient as RpmApiClient
from pulpcore.client.pulp_rpm import Configuration as RpmConfiguration
from pulpcore.client.pulp_rpm import ContentPackagesApi, RpmPackageResponse
from pulpcore.client.pulp_rpm.exceptions import ApiException as RpmApiException
from pulpcore.client.pulpcore.configuration import Configuration
from pulpcore.client.pulpcore.api_client import ApiClient
from pulpcore.client.pulpcore.exceptions import ApiException
from pulpcore.client.pulpcore.api.tasks_api import TasksApi
from pulpcore.client.pulpcore.api.uploads_api import UploadsApi
from pulpcore.client.pulpcore.api.artifacts_api import ArtifactsApi
from urllib3.exceptions import HTTPError
from urllib3.util.retry import Retry

from sign_node.config import DEFAULT_PULP_CHUNK_WORKERS
from sign_node.uploaders.base import BaseUploader, UploadError
from sign_node.uploaders.pulp_session import PulpSession
from sign_node.utils.file_utils import hash_file
from sign_node.models import Artifact

__all__ = ["PulpBaseUploader", "PulpRpmUploader"]

DEFAULT_TIMEOUT = 45  # seconds
DEFAULT_UPLOAD_RETRIES = 3
UPLOAD_RETRY_DELAY = 10  # seconds, multiplied by the attempt number
# No transport retries: urllib3 would re-send a PUT chunk after a read
# timeout, and Pulp appends it a second time; a failed file is started
# over in upload_single_file() instead. A Retry instance rather than
# False, which urllib3 converts (and logs) on every request.
NO_RETRIES = Retry(total=False, redirect=0)


class TaskFailedError(Exception):
    pass


class PulpBaseUploader(BaseUploader):
    """
    Handles uploads to Pulp server.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        chunk_size: int,
        requests_timeout: int = DEFAULT_TIMEOUT,
        upload_retries: int = DEFAULT_UPLOAD_RETRIES,
        chunk_workers: int = DEFAULT_PULP_CHUNK_WORKERS,
    ):
        """
        Initiate uploader.

        Parameters
        ----------
        host : str
            Pulp HTTP address.
        username : str
            User name to authenticate in Pulp.
        password : str
            User password.
        chunk_size : int
            Size of chunk to split files during the upload.
        requests_timeout : int
            Timeout of every request to Pulp, in seconds.
        upload_retries : int
            How many times a file upload is started over after a
            connection error, a timeout or a server error.
        chunk_workers : int
            Maximum number of chunks of one large file uploaded in
            parallel.
        """
        self._requests_timeout = requests_timeout
        self._upload_retries = upload_retries
        self._session = PulpSession(
            host, username, password, requests_timeout=requests_timeout
        )
        api_client = self._prepare_api_client(host)
        self._uploads_client = UploadsApi(api_client=api_client)
        self._tasks_client = TasksApi(api_client=api_client)
        self._artifacts_client = ArtifactsApi(api_client=api_client)
        self._chunk_workers = chunk_workers
        self._chunk_size = chunk_size
        self._logger = logging.getLogger(__file__)

    def _prepare_api_client(self, host: str) -> ApiClient:
        """

        Parameters
        ----------
        host : str

        Returns
        -------
        ApiClient

        """
        # No username/password, otherwise the client sends Basic auth
        api_configuration = Configuration(host=host, retries=NO_RETRIES)
        return self._session.authenticate(
            ApiClient(configuration=api_configuration)
        )

    def reset_connections(self):
        """
        Closes the pooled connections, see PulpSession.reset_connections().
        """
        self._session.reset_connections()

    def _wait_for_task_completion(self, task_href: str) -> dict:
        """

        Parameters
        ----------
        task_href : str

        Returns
        -------
        dict
            Task final state

        """
        result = self._tasks_client.read(
            task_href, _request_timeout=self._requests_timeout
        )
        delay = 0.3
        while result.state not in ("failed", "completed"):
            time.sleep(delay)
            delay = min(delay * 2, 5)
            result = self._tasks_client.read(
                task_href, _request_timeout=self._requests_timeout
            )
        if result.state == "failed":
            raise TaskFailedError(
                f"task {task_href} has failed, " f"details: {result}"
            )
        return result

    def _create_upload(self, file_path: str) -> typing.Tuple[str, int]:
        """

        Parameters
        ----------
        file_path : str
            Path to the file.

        Returns
        -------
        tuple
            Upload reference and file size.

        """
        file_size = os.path.getsize(file_path)
        response = self._uploads_client.create(
            {"size": file_size}, _request_timeout=self._requests_timeout
        )
        return response.pulp_href, file_size

    def _commit_upload(self, reference: str, file_sha256: str) -> str:
        """
        Commits upload and waits until upload will be transformed to artifact.
        Returns artifact reference upon completion.

        Parameters
        ----------
        reference : str
            Upload reference in Pulp.
        file_sha256 : str
            Pre-computed SHA256 of the file.

        Returns
        -------
        str
            Reference to the created resource.

        """
        response = self._uploads_client.commit(
            reference,
            {"sha256": file_sha256},
            _request_timeout=self._requests_timeout,
        )
        task_result = self._wait_for_task_completion(response.task)
        return task_result.created_resources[0]

    def _put_chunk(
        self, file_path: str, reference: str, offset: int, total_size: int
    ):
        """
        Sends one chunk of the file to the upload.

        Parameters
        ----------
        file_path : str
            Path to the file.
        reference : str
            Upload reference in Pulp.
        offset : int
            Position of the chunk in the file.
        total_size : int
            Size of the whole file.

        """
        expected = min(self._chunk_size, total_size - offset)
        with open(file_path, 'rb') as f:
            f.seek(offset)
            chunk = f.read(expected)
        # The range is the expected one: if the file got shorter, Pulp
        # rejects the chunk because its size does not match the range
        self._uploads_client.update(
            f'bytes {offset}-{offset + expected - 1}/{total_size}',
            reference,
            (os.path.basename(file_path), chunk),
            _request_timeout=self._requests_timeout,
        )

    def _put_large_file(self, file_path: str, reference: str):
        """
        Sends the file to the upload in chunks of self._chunk_size bytes,
        up to self._chunk_workers of them at once. Pulp accepts the chunks
        in any order.

        Parameters
        ----------
        file_path : str
            Path to the file.
        reference : str
            Upload reference in Pulp.

        """
        start = time.monotonic()
        total_size = os.path.getsize(file_path)
        offsets = range(0, total_size, self._chunk_size)
        workers = min(self._chunk_workers, len(offsets))
        executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix='pulp_chunk'
        )
        try:
            futures = [
                executor.submit(
                    self._put_chunk, file_path, reference, offset, total_size
                )
                for offset in offsets
            ]
            for future in as_completed(futures):
                future.result()
        finally:
            # On an error, do not send the remaining chunks: the whole
            # file is started over with a new upload
            executor.shutdown(wait=True, cancel_futures=True)
        self._logger.info(
            "Sent %s (%d bytes) in %d chunks, %d at once, in %.2f s",
            os.path.basename(file_path),
            total_size,
            len(offsets),
            workers,
            time.monotonic() - start,
        )

    def _send_file(self, file_path: str) -> typing.Tuple[str, str]:
        file_sha256 = hash_file(file_path, hash_type="sha256")
        reference = self.check_if_artifact_exists(file_sha256)
        if reference:
            return file_sha256, reference
        reference, file_size = self._create_upload(file_path)
        if file_size > self._chunk_size:
            self._put_large_file(file_path, reference)
        else:
            self._uploads_client.update(
                f"bytes 0-{file_size - 1}/{file_size}",
                reference,
                file_path,
                _request_timeout=self._requests_timeout,
            )
        artifact_href = self._commit_upload(reference, file_sha256)
        return file_sha256, artifact_href

    def check_if_artifact_exists(self, sha256: str) -> str:
        response = self._artifacts_client.list(
            sha256=sha256, _request_timeout=self._requests_timeout
        )
        if response.results:
            return response.results[0].pulp_href

    def upload(self, artifacts_dir: str, **kwargs) -> List[Artifact]:
        """

        Parameters
        ----------
        artifacts_dir : str
            Path to files that need to be uploaded.

        Returns
        -------
        list
            List of the references to the artifacts inside Pulp

        """
        artifacts = []
        errored_uploads = []
        for artifact in self.get_artifacts_list(artifacts_dir):
            try:
                artifacts.append(self.upload_single_file(artifact))
            except Exception as e:
                self._logger.error(
                    "Cannot upload %s, error: %s", artifact, e, exc_info=e
                )
                errored_uploads.append(artifact)
        # TODO: Decide what to do with successfully uploaded artifacts
        #  in case of errors during upload.
        if errored_uploads:
            raise UploadError(f"Unable to upload files: {errored_uploads}")
        return artifacts

    def upload_single_file(
        self,
        filename: str,
        artifact_type: typing.Optional[str] = None,
    ) -> Artifact:
        """

        Parameters
        ----------
        filename : str
            Path to file that need to be uploaded.
        artifact_type : str or None
            Type of uploaded artifact

        Returns
        -------
        Artifact
        """
        for attempt in range(1, self._upload_retries + 2):
            try:
                file_sha256, reference = self._send_file(filename)
                break
            except (ApiException, RpmApiException) as e:
                if e.status in (401, 403):
                    # The session has expired (after 2 weeks by default),
                    # log in again and retry once
                    self._session.login()
                    file_sha256, reference = self._send_file(filename)
                    break
                # Status 0 is an SSL error from the client
                if 0 < e.status < 500 or attempt > self._upload_retries:
                    raise
                error = e
            except HTTPError as e:
                # urllib3: no connection, timeout, connection reset
                if attempt > self._upload_retries:
                    raise
                error = e
            # Start the file over: Pulp returns what the earlier attempt
            # managed to create (artifacts are looked up by checksum,
            # packages by pkgId), so nothing is uploaded twice
            delay = UPLOAD_RETRY_DELAY * attempt
            self._logger.warning(
                "Cannot upload %s (attempt %d of %d), retrying in %d s: %s",
                filename,
                attempt,
                self._upload_retries + 1,
                delay,
                error,
            )
            time.sleep(delay)
        if artifact_type is None:
            artifact_type = 'rpm' if filename.endswith('.rpm') else 'build_log'
        return Artifact(
            name=os.path.basename(filename),
            href=reference,
            type=artifact_type,
            sha256=file_sha256,
        )


class PulpRpmUploader(PulpBaseUploader):
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        chunk_size: int,
        **kwargs,
    ):
        super().__init__(host, username, password, chunk_size, **kwargs)
        rpm_api_client = self._session.authenticate(
            RpmApiClient(
                configuration=RpmConfiguration(host=host, retries=NO_RETRIES)
            )
        )
        self._packages_client = ContentPackagesApi(api_client=rpm_api_client)

    def _send_rpm(self, file_path: str, file_sha256: str) -> str:
        """
        Creates RPM content with the synchronous upload endpoint, so no
        Pulp tasks have to be queued and polled.

        Parameters
        ----------
        file_path : str
            Path to the RPM file.
        file_sha256 : str
            Pre-computed SHA256 of the file.

        Returns
        -------
        str
            Reference to the RPM package.

        """
        if os.path.getsize(file_path) > self._chunk_size:
            package = self._post_rpm_chunked(file_path)
        else:
            package = self._packages_client.upload(
                file=file_path, _request_timeout=self._requests_timeout
            )

        if package.sha256 != file_sha256:
            raise UploadError(
                f"{file_path} checksum mismatch: expected {file_sha256}, "
                f"Pulp has {package.sha256}"
            )
        return package.pulp_href

    def _post_rpm_chunked(self, file_path: str) -> RpmPackageResponse:
        """
        Uploads a large RPM in chunks and creates the package from
        the resulting upload.

        Parameters
        ----------
        file_path: str
            Path to the RPM file
        """
        upload_href, _ = self._create_upload(file_path)
        try:
            self._put_large_file(file_path, upload_href)
            return self._packages_client.upload(
                upload=upload_href, _request_timeout=self._requests_timeout
            )
        finally:
            # Unlike the commit task, the synchronous endpoint keeps
            # the upload and its chunks, so remove them ourselves
            try:
                self._uploads_client.delete(
                    upload_href, _request_timeout=self._requests_timeout
                )
            except Exception as e:
                self._logger.warning(
                    "Cannot delete upload %s: %s", upload_href, e
                )

    def _send_file(self, file_path: str) -> tuple[str, str]:
        if not file_path.endswith(".rpm"):
            return super()._send_file(file_path)
        file_sha256 = hash_file(file_path, hash_type="sha256")
        return file_sha256, self._send_rpm(file_path, file_sha256)

    def get_artifacts_list(self, artifacts_dir: str) -> List[str]:
        """

        Returns the list of the files in artifacts directory
        that need to be uploaded.

        Parameters
        ----------
        artifacts_dir : str
            Path to artifacts directory.

        Returns
        -------
        list
            List of files.

        """
        artifacts = []
        for file_ in super().get_artifacts_list(artifacts_dir):
            if file_.endswith(".rpm"):
                artifacts.append(file_)
            elif file_.endswith(".log"):
                artifacts.append(file_)
            elif file_.endswith(".cfg"):
                artifacts.append(file_)
        return artifacts
