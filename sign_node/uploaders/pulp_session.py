from http.cookies import SimpleCookie
from typing import Optional

from pulpcore.client.pulpcore import LoginApi
from pulpcore.client.pulpcore.api_client import ApiClient
from pulpcore.client.pulpcore.configuration import Configuration

from sign_node.uploaders.base import UploadError

__all__ = ["PulpSession"]


class PulpSession:
    """
    Logs in to Pulp once and authenticates API clients with the session.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        requests_timeout: Optional[int] = None,
    ):
        """
        Parameters
        ----------
        host : str
            Pulp HTTP address.
        username : str
            User name to authenticate in Pulp.
        password : str
            User password.
        requests_timeout : int or None
            Timeout of the login request.
        """
        self._host = host.rstrip("/")
        self._username = username
        self._password = password
        self._requests_timeout = requests_timeout
        # Every authenticated client, so a re-login updates all of them
        self._api_clients = []
        self.login()

    def login(self):
        """
        Logs in to Pulp and applies the new session to every client.
        """
        login_client = ApiClient(
            configuration=Configuration(
                host=self._host,
                username=self._username,
                password=self._password,
            )
        )
        # login() and login_with_http_info() keep only one of the two
        # Set-Cookie headers, so read them from the raw response
        response = LoginApi(login_client).login_without_preload_content(
            _request_timeout=self._requests_timeout
        )
        try:
            if response.status != 201:
                raise UploadError(f"Pulp login failed: HTTP {response.status}")
            cookies = SimpleCookie()
            for header in response.headers.getlist("Set-Cookie"):
                cookies.load(header)
        finally:
            response.release_conn()
        self._csrf_token = cookies["csrftoken"].value
        self._cookie = (
            f"sessionid={cookies['sessionid'].value}; "
            f"csrftoken={self._csrf_token}"
        )
        for api_client in self._api_clients:
            self._apply(api_client)

    def authenticate(self, api_client):
        """
        Makes an API client use the session, also after a later re-login.
        The client must be created without username and password, otherwise
        it sends Basic auth.

        Parameters
        ----------
        api_client
            ApiClient of any Pulp SDK.

        Returns
        -------
        The same API client.
        """
        self._api_clients.append(api_client)
        self._apply(api_client)
        return api_client

    def reset_connections(self):
        """
        Closes the pooled connections of every client. An idle connection
        is dropped silently on the way to Pulp and the next request on it
        only times out, so the uploads of a task start on fresh ones.
        """
        for api_client in self._api_clients:
            api_client.rest_client.pool_manager.clear()

    def _apply(self, api_client):
        api_client.cookie = self._cookie
        # Django requires the CSRF token for unsafe methods with a session,
        # and checks the Referer over HTTPS
        api_client.set_default_header("X-CSRFToken", self._csrf_token)
        api_client.set_default_header("Referer", f"{self._host}/")
