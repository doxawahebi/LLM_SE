"""Sailor backend configuration — reads from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://sailor:sailor@postgres:5432/sailor"
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/0"
    celery_result_backend: str = "redis://redis:6379/1"

    s3_endpoint: str = "http://minio:9000"
    s3_access_key: str = "sailor"
    s3_secret_key: str = "sailor123"
    s3_bucket: str = "sailor-artifacts"

    jwt_secret: str = "dev-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_expire_minutes: int = 15
    jwt_refresh_expire_days: int = 7

    anthropic_api_key: str = ""
    anthropic_api_option: str = "false"
    gemini_api_key: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
