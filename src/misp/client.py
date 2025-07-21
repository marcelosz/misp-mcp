import logging
from typing import Optional

from pymisp import PyMISP

from ..config import Settings

logger = logging.getLogger(__name__)


class MISPClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._client: Optional[PyMISP] = None

    @property
    def client(self) -> PyMISP:
        if self._client is None:
            self._client = PyMISP(
                url=self.settings.misp_url,
                key=self.settings.misp_api_key,
                ssl=self.settings.misp_verify_ssl,
                debug=False,
            )
        return self._client

    def test_connection(self) -> dict:
        try:
            response = self.client.get_version()
            if isinstance(response, dict):
                return {
                    "status": "connected",
                    "version": response.get("version", "unknown"),
                    "pymisp_version": response.get("pymisp_version", "unknown"),
                }
            else:
                return {"status": "error", "message": "Invalid response from MISP server"}
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return {"status": "error", "message": str(e)}

    def get_version(self) -> dict:
        try:
            return self.client.get_version()
        except Exception as e:
            logger.error(f"Failed to get version: {e}")
            raise
