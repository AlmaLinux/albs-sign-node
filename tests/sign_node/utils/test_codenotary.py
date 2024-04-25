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
