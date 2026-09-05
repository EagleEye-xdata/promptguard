from pathlib import Path
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]

class Settings(BaseSettings):
    database_url: str = f"sqlite:///{ROOT / 'promptguard.db'}"
    redis_url: str = "redis://localhost:6379/0"
    judge_provider: str = "none"
    judge_model: str = "gpt-4o-mini"
    openai_judge_model: str = "gpt-4o-mini"
    anthropic_judge_model: str = "claude-3-5-haiku-latest"
    google_judge_model: str = "gemini-2.0-flash"
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    google_api_key: str | None = None
    encryption_key: str = Field(default="",validation_alias=AliasChoices("EAGLEI_ENCRYPTION_KEY","ENCRYPTION_KEY"))
    cors_origins: str = Field(default="http://localhost:5173",validation_alias=AliasChoices("EAGLEI_CORS_ORIGINS","CORS_ORIGINS"))
    proxy_api_key: str = Field(default="",validation_alias=AliasChoices("EAGLEI_PROXY_API_KEY","PROXY_API_KEY"))
    demo_target_url: str = "http://localhost:8001/v1/chat/completions"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
