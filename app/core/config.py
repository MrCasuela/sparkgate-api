from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    supabase_url: str = "https://your-project.supabase.co"
    supabase_key: str = "your-anon-key"
    supabase_service_role_key: str = ""
    supabase_db_url: str = ""
    ollama_url: str = "http://localhost:11434"
    hibp_api_url: str = "https://api.pwnedpasswords.com"
    env: str = "development"
    cors_origins: str = "chrome-extension://*,http://localhost:3000"
    ai_backend: str = "ollama"
    openrouter_api_key: str = ""
    openrouter_model: str = "meta-llama/llama-3.1-8b-instruct"
    vault_master_key: str = ""
    totp_master_key: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
