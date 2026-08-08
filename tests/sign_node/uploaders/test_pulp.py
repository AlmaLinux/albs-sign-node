import operator
import os
import re
import threading
from unittest.mock import Mock, patch

from pyfakefs.fake_filesystem_unittest import TestCase

from sign_node.models import Artifact
from sign_node.uploaders.pulp import PulpRpmUploader
from sign_node.utils.file_utils import hash_file


class TestPulpRpmUploader(TestCase):

    def setUp(self):
        self.setUpPyfakefs()

        self.fs.create_dir('/build_dir/tmp')

        self.file_map = {}
        self.file_lst = []
        self.file_paths = sorted([
            '/build_dir/package.rpm',
            '/build_dir/build.log',
            '/build_dir/config.cfg'
        ])

        for file_path in self.file_paths:
            self.fs.create_file(file_path, contents=file_path)
            hsh = hash_file(file_path, hash_type="sha256")
            artifact = Artifact(
                name=os.path.basename(file_path),
                type='rpm' if file_path.endswith('.rpm') else 'build_log',
                href='pulp_href' + str(len(self.file_map)),
                sha256=hsh,
            )
            self.file_map[hsh] = artifact
            self.file_lst.append(artifact)

    def test_get_artifacts_list(self):
        uploader = PulpRpmUploader('localhost', 'user', 'password', 42)
        files1 = uploader.get_artifacts_list('/build_dir')
        files1.sort()
        assert files1 == self.file_paths

    def test_upload_funcs(self):
        class ArtifactsApi:
            def __init__(self, *_, **__):
                pass

            def list(_, sha256):
                assert sha256 in self.file_map
                data = Mock()
                data.pulp_href = self.file_map[sha256].href
                response = Mock()
                response.results = [data]
                return response

        with patch('sign_node.uploaders.pulp.ArtifactsApi', new=ArtifactsApi):
            uploader = PulpRpmUploader('localhost', 'user', 'password', 42)
            rpm_pkg = uploader.upload_single_file('/build_dir/package.rpm')
            assert rpm_pkg in self.file_lst

            files = uploader.upload('/build_dir')
            files.sort(key=operator.attrgetter('name'))
            assert files == self.file_lst

    def test_send_file(self):
        f_path = '/build_dir/package.rpm'
        f_hash = hash_file(f_path, hash_type="sha256")
        f_size = os.path.getsize(f_path)
        f_href = self.file_map[f_hash].href

        class UploadsApi:
            def __init__(self, *_, **__):
                pass

            def create(_, opts):
                assert opts['size'] == f_size
                response = Mock()
                response.pulp_href = f_href
                return response

            def update(_, content_range, upload_href, file):
                assert upload_href == f_href
                assert file == f_path

            def commit(_, upload_href, upload_commit):
                assert upload_href == f_href
                assert upload_commit['sha256'] == f_hash
                response = Mock()
                response.task = TasksApi.TASK_HREF
                return response

        class TasksApi:
            TASK_HREF = 'task1'
            def __init__(self, *_, **__):
                pass

            def read(self, task_href):
                assert task_href == self.TASK_HREF
                result = Mock()
                result.created_resources = [f_href]
                result.state = 'completed'
                return result

        with (
            patch('sign_node.uploaders.pulp.UploadsApi', new=UploadsApi),
            patch('sign_node.uploaders.pulp.TasksApi', new=TasksApi),
            patch.object(PulpRpmUploader, 'check_if_artifact_exists', return_value=None)
        ):
            uploader = PulpRpmUploader('localhost', 'user', 'password', f_size)
            file_sha256, artifact_href = uploader._send_file(f_path)
            assert file_sha256 == f_hash
            assert artifact_href == f_href

    def test_send_file_direct_artifact(self):
        """Verify that small files (< chunk_size) use the direct artifact
        creation path and never touch UploadsApi."""
        f_path = '/build_dir/small.rpm'
        self.fs.create_file(f_path, contents='small data')
        f_hash = hash_file(f_path, hash_type='sha256')
        artifact_href = '/pulp/api/v3/artifacts/direct-small/'
        chunk_size = 100  # larger than the 10-byte file

        class MockArtifactsApi:
            def __init__(self, *_, **__):
                pass

            def create(_, file_path, sha256=None):
                assert file_path == f_path
                assert sha256 == f_hash
                response = Mock()
                response.pulp_href = artifact_href
                return response

            def list(_, sha256=None):
                response = Mock()
                response.results = []
                return response

        mock_uploads = Mock()
        mock_tasks = Mock()

        with (
            patch('sign_node.uploaders.pulp.ArtifactsApi',
                  new=MockArtifactsApi),
            patch('sign_node.uploaders.pulp.UploadsApi',
                  return_value=mock_uploads),
            patch('sign_node.uploaders.pulp.TasksApi',
                  return_value=mock_tasks),
        ):
            uploader = PulpRpmUploader('localhost', 'user', 'password',
                                       chunk_size)
            result_hash, result_href = uploader._send_file(f_path)

        assert result_hash == f_hash
        assert result_href == artifact_href
        # UploadsApi methods must never be called for small files
        assert not mock_uploads.create.called
        assert not mock_uploads.update.called
        assert not mock_uploads.commit.called

    def test_send_large_file(self):
        """Verify parallel chunked upload produces correct Content-Range
        headers and the right number of update() calls."""
        f_path = '/build_dir/large.rpm'
        self.fs.create_file(f_path, contents='x' * 100)
        f_hash = hash_file(f_path, hash_type='sha256')
        f_size = 100
        chunk_size = 30  # 4 chunks: 30+30+30+10
        upload_href = '/pulp/api/v3/uploads/large-upload/'
        artifact_href = '/pulp/api/v3/artifacts/large-artifact/'

        # Thread-safe list to record all update() calls
        update_calls = []
        lock = threading.Lock()

        class MockUploadsApi:
            def __init__(self, *_, **__):
                pass

            def create(_, opts):
                assert opts['size'] == f_size
                response = Mock()
                response.pulp_href = upload_href
                return response

            def update(_, content_range, href, file_path):
                with lock:
                    update_calls.append(content_range)
                assert href == upload_href

            def commit(_, href, upload_commit):
                assert href == upload_href
                assert upload_commit['sha256'] == f_hash
                response = Mock()
                response.task = 'task-large'
                return response

        class MockTasksApi:
            def __init__(self, *_, **__):
                pass

            def read(self, task_href):
                assert task_href == 'task-large'
                result = Mock()
                result.created_resources = [artifact_href]
                result.state = 'completed'
                return result

        with (
            patch('sign_node.uploaders.pulp.UploadsApi', new=MockUploadsApi),
            patch('sign_node.uploaders.pulp.TasksApi', new=MockTasksApi),
            patch.object(PulpRpmUploader, 'check_if_artifact_exists',
                         return_value=None),
        ):
            uploader = PulpRpmUploader('localhost', 'user', 'password',
                                       chunk_size)
            file_sha256, result_href = uploader._send_file(f_path)

        # Correct return values
        assert file_sha256 == f_hash
        assert result_href == artifact_href

        # Exactly 4 chunks uploaded
        assert len(update_calls) == 4

        # Parse Content-Range headers and verify full coverage
        # Expected: bytes 0-29/100, bytes 30-59/100, bytes 60-89/100,
        #           bytes 90-99/100
        pattern = re.compile(r'bytes (\d+)-(\d+)/(\d+)')
        ranges = []
        for cr in update_calls:
            m = pattern.match(cr)
            assert m, f'Invalid Content-Range header: {cr}'
            start, end, total = int(m.group(1)), int(m.group(2)), int(m.group(3))
            assert total == f_size
            ranges.append((start, end))

        # Sort by start offset and verify contiguous, non-overlapping coverage
        ranges.sort()
        assert ranges == [(0, 29), (30, 59), (60, 89), (90, 99)]

    def test_send_large_file_chunk_error(self):
        """Verify that if one chunk upload raises, the exception propagates."""
        f_path = '/build_dir/error.rpm'
        self.fs.create_file(f_path, contents='y' * 100)
        f_size = 100
        chunk_size = 30
        upload_href = '/pulp/api/v3/uploads/error-upload/'

        call_count = {'n': 0}
        count_lock = threading.Lock()

        class MockUploadsApi:
            def __init__(self, *_, **__):
                pass

            def create(_, opts):
                response = Mock()
                response.pulp_href = upload_href
                return response

            def update(_, content_range, href, file_path):
                with count_lock:
                    call_count['n'] += 1
                    if call_count['n'] == 2:
                        raise RuntimeError('chunk upload failed')

            def commit(_, href, upload_commit):
                response = Mock()
                response.task = 'task-err'
                return response

        class MockTasksApi:
            def __init__(self, *_, **__):
                pass

            def read(self, task_href):
                result = Mock()
                result.created_resources = ['/artifact/']
                result.state = 'completed'
                return result

        with (
            patch('sign_node.uploaders.pulp.UploadsApi', new=MockUploadsApi),
            patch('sign_node.uploaders.pulp.TasksApi', new=MockTasksApi),
            patch.object(PulpRpmUploader, 'check_if_artifact_exists',
                         return_value=None),
        ):
            uploader = PulpRpmUploader('localhost', 'user', 'password',
                                       chunk_size)
            try:
                uploader._send_file(f_path)
                assert False, 'Expected RuntimeError to propagate'
            except RuntimeError as e:
                assert 'chunk upload failed' in str(e)

    def test_configurable_upload_workers(self):
        """Verify that a custom upload_workers value reaches ThreadPoolExecutor."""
        from concurrent.futures import ThreadPoolExecutor as RealTPE

        f_path = '/build_dir/workers.rpm'
        self.fs.create_file(f_path, contents='w' * 100)
        f_hash = hash_file(f_path, hash_type='sha256')
        f_size = 100
        chunk_size = 30  # triggers large file path (100 > 30)
        upload_href = '/pulp/api/v3/uploads/workers-upload/'
        artifact_href = '/pulp/api/v3/artifacts/workers-artifact/'

        captured_max_workers = {}

        class MockUploadsApi:
            def __init__(self, *_, **__):
                pass

            def create(_, opts):
                response = Mock()
                response.pulp_href = upload_href
                return response

            def update(_, content_range, href, file_path):
                pass

            def commit(_, href, upload_commit):
                response = Mock()
                response.task = 'task-workers'
                return response

        class MockTasksApi:
            def __init__(self, *_, **__):
                pass

            def read(self, task_href):
                result = Mock()
                result.created_resources = [artifact_href]
                result.state = 'completed'
                return result

        def spy_tpe(*args, **kwargs):
            captured_max_workers['value'] = kwargs.get('max_workers')
            return RealTPE(*args, **kwargs)

        with (
            patch('sign_node.uploaders.pulp.UploadsApi', new=MockUploadsApi),
            patch('sign_node.uploaders.pulp.TasksApi', new=MockTasksApi),
            patch.object(PulpRpmUploader, 'check_if_artifact_exists',
                         return_value=None),
            patch('sign_node.uploaders.pulp.ThreadPoolExecutor',
                  side_effect=spy_tpe),
        ):
            uploader = PulpRpmUploader('localhost', 'user', 'password',
                                       chunk_size, upload_workers=2)
            uploader._send_file(f_path)

        # ThreadPoolExecutor was called with the custom value
        assert captured_max_workers.get('value') == 2

    def test_default_upload_workers(self):
        """Verify the default upload_workers is 4 when not explicitly set."""
        with (
            patch('sign_node.uploaders.pulp.UploadsApi'),
            patch('sign_node.uploaders.pulp.TasksApi'),
            patch('sign_node.uploaders.pulp.ArtifactsApi'),
        ):
            uploader = PulpRpmUploader('localhost', 'user', 'password', 42)
        assert uploader._upload_workers == 4

    def test_upload_timing_log_direct(self):
        """Verify timing log is emitted for direct artifact upload path."""
        f_path = '/build_dir/timed_small.rpm'
        self.fs.create_file(f_path, contents='tiny')
        f_hash = hash_file(f_path, hash_type='sha256')
        artifact_href = '/pulp/api/v3/artifacts/timed-small/'
        chunk_size = 100  # larger than file -> direct artifact path

        class MockArtifactsApi:
            def __init__(self, *_, **__):
                pass

            def create(_, file_path, sha256=None):
                response = Mock()
                response.pulp_href = artifact_href
                return response

            def list(_, sha256=None):
                response = Mock()
                response.results = []
                return response

        with (
            patch('sign_node.uploaders.pulp.ArtifactsApi',
                  new=MockArtifactsApi),
            patch('sign_node.uploaders.pulp.UploadsApi'),
            patch('sign_node.uploaders.pulp.TasksApi'),
            self.assertLogs(level='INFO') as cm,
        ):
            uploader = PulpRpmUploader('localhost', 'user', 'password',
                                       chunk_size)
            uploader._send_file(f_path)

        # Find the timing log line
        timing_logs = [m for m in cm.output if 'Upload complete' in m]
        assert len(timing_logs) >= 1, f'Expected timing log, got: {cm.output}'
        log_line = timing_logs[0]
        assert 'direct artifact' in log_line
        assert 'timed_small.rpm' in log_line
        # Verify a time value is present (e.g. "0.00s" or "1.23s")
        assert re.search(r'\d+\.\d+s', log_line), \
            f'Expected elapsed time in log: {log_line}'

    def test_upload_timing_log_chunked(self):
        """Verify timing log is emitted for chunked upload path."""
        f_path = '/build_dir/timed_large.rpm'
        self.fs.create_file(f_path, contents='z' * 100)
        f_hash = hash_file(f_path, hash_type='sha256')
        f_size = 100
        chunk_size = 30  # triggers large file path
        upload_href = '/pulp/api/v3/uploads/timed-large/'
        artifact_href = '/pulp/api/v3/artifacts/timed-large/'

        class MockUploadsApi:
            def __init__(self, *_, **__):
                pass

            def create(_, opts):
                response = Mock()
                response.pulp_href = upload_href
                return response

            def update(_, content_range, href, file_path):
                pass

            def commit(_, href, upload_commit):
                response = Mock()
                response.task = 'task-timed'
                return response

        class MockTasksApi:
            def __init__(self, *_, **__):
                pass

            def read(self, task_href):
                result = Mock()
                result.created_resources = [artifact_href]
                result.state = 'completed'
                return result

        with (
            patch('sign_node.uploaders.pulp.UploadsApi', new=MockUploadsApi),
            patch('sign_node.uploaders.pulp.TasksApi', new=MockTasksApi),
            patch.object(PulpRpmUploader, 'check_if_artifact_exists',
                         return_value=None),
            self.assertLogs(level='INFO') as cm,
        ):
            uploader = PulpRpmUploader('localhost', 'user', 'password',
                                       chunk_size)
            uploader._send_file(f_path)

        # Find the timing log line
        timing_logs = [m for m in cm.output if 'Upload complete' in m]
        assert len(timing_logs) >= 1, f'Expected timing log, got: {cm.output}'
        log_line = timing_logs[0]
        assert 'chunks' in log_line
        assert 'timed_large.rpm' in log_line
        # Verify a time value is present
        assert re.search(r'\d+\.\d+s', log_line), \
            f'Expected elapsed time in log: {log_line}'
