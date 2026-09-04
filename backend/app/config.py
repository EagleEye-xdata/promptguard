from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]

class Settings(BaseSettings):
    database_url: str = f"sqlite:///{ROOT / 'promptguard.db'}"
    redis_url: str = "redis://localhost:6379/0"
    judge_provider: str = "none"
    judge_model: str = "gpt-4o-mini"
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    encryption_key: str = ""
    demo_target_url: str = "http://localhost:8001/v1/chat/completions"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
