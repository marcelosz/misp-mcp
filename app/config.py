from pydantic import ConfigDict
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )

    misp_url: str
    misp_api_key: str
    misp_verify_ssl: bool = True

    mcp_server_host: str = "localhost"
    mcp_server_port: int = 8000


def get_settings() -> Settings:
    return Settings()
