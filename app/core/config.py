from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    supabase_url: str = "https://your-project.supabase.co"
    supabase_key: str = "your-anon-key"
    ollama_url: str = "http://localhost:11434"
    hibp_api_url: str = "https://api.pwnedpasswords.com"
    env: str = "development"
    cors_origins: str = "chrome-extension://*,http://localhost:3000"
    ai_backend: str = "ollama"
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
