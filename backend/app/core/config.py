import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    PROJECT_NAME: str = "API Sentinel"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # Security / Auth
    SECRET_KEY: str = "api-sentinel-ultra-secure-secret-key-change-in-production-32bytes"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Encryption at rest key (Fernet 32-byte url-safe base64 string)
    ENCRYPTION_KEY: str = "k8F-4Lp2T8s_vV91-o1_0a3B2c4D5e6F7g8H9i0J1k="
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./api_sentinel.db"
    POSTGRES_SERVER: Optional[str] = None
    POSTGRES_USER: Optional[str] = None
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_DB: Optional[str] = None
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:3001", "http://localhost:8000", "http://127.0.0.1:3000"]
    
    # SSRF Protection & Scanner Safety
    ALLOW_LOCAL_TARGETS: bool = True  # For dev / demo testing
    MAX_SCAN_REQUESTS: int = 250
    SCAN_REQUEST_TIMEOUT: float = 8.0
    SCAN_MAX_CONCURRENT_REQUESTS: int = 5
    ALLOWED_DOMAINS: List[str] = []
    BLOCKED_DOMAINS: List[str] = ["metadata.google.internal", "169.254.169.254"]
    
    # Monitoring
    DEFAULT_MONITOR_INTERVAL_MINUTES: int = 15
    
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
