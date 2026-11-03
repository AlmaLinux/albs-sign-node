import threading
from unittest.mock import Mock, patch

from sign_node.utils.codenotary import Codenotary


def test_codenotary():
    wrapper = Mock()
    wrapper.authenticate_file.return_value = {'foo': 'bar'}
    wrapper.notarize_file.return_value = {'value': {'Hash': '1234'}}

    with patch('sign_node.utils.codenotary.ImmudbWrapper', return_value=wrapper):
        immudb = Codenotary()

        result = immudb.verify_artifact('/test/file.txt')
        wrapper.authenticate_file.assert_called_with('/test/file.txt')
        assert result == {'foo': 'bar'}

        hash_val = immudb.notarize_artifact('/test/file.txt', {})
        wrapper.notarize_file.assert_called_with('/test/file.txt', {'unsigned_hash': None})
        assert hash_val == '1234'


def test_codenotary_client_per_thread():
    with patch(
        'sign_node.utils.codenotary.ImmudbWrapper', side_effect=Mock
    ) as wrapper_cls:
        immudb = Codenotary()
        wrappers = [immudb.wrapper]
        threads = [
            threading.Thread(target=lambda: wrappers.append(immudb.wrapper))
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert wrapper_cls.call_count == 3
    assert wrappers[0] is immudb.wrapper
    assert len({id(w) for w in wrappers}) == 3
