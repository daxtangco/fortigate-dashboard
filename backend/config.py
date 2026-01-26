from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Configuration loaded from .env file"""
    
    # Syslog Receiver
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    
    # Server
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = True
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
