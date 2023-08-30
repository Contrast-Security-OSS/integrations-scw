import json
import requests

from dataclasses import dataclass
from typing import Dict, List


class RequestHandlerException(Exception):
    pass


@dataclass
class Response:
    status_code: int
    message: str
    data: List[Dict]


class RequestHandler:
    def __init__(self, session: requests.Session):
        # Configure a requests session with the headers for all requests
        self.session = session

    def _request(self, http_method: str, url: str, params: Dict = None, data: Dict = None) -> Response:
        # Perform the HTTP request or raise an exception
        try: 
            response = self.session.request(method=http_method, url=url, params=params, json=data)
        except requests.exceptions.RequestException as e: 
            raise RequestHandlerException("Request failed") from e
        
        # Deserialize the JSON response to a Python object or raise an exception
        try: 
            data_out = response.json()
        except (ValueError, json.JSONDecodeError) as e: 
            raise RequestHandlerException("Bad JSON in response") from e
        
        # If status_code in 200-299 range, return success Result with data, otherwise raise exception
        if 299 >= response.status_code >= 200:
            return Response(response.status_code, message=response.reason, data=data_out)
        raise RequestHandlerException(f"Request failed with status code {response.status_code}: {response.reason}")

    def get(self, url: str, params: Dict = None) -> Response:
        return self._request(http_method="GET", url=url, params=params)

    def post(self, url: str, params: Dict = None, data: Dict = {}) -> Response:
        return self._request(http_method="POST", url=url, params=params, data=data)
