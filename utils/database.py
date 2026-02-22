"""
Supabase database client wrapper.

Provides a single configured Supabase client instance used across the application.
All database operations go through this module — never write raw SQL.

Setup:
    1. Create a Supabase project at https://supabase.com
    2. Copy Project URL and anon key into .env as SUPABASE_URL and SUPABASE_KEY
    3. Run the SQL schema from PLAN.md in the Supabase SQL Editor
"""

from supabase import create_client, Client

from config import config

_client: Client | None = None


def get_supabase_client() -> Client:
    """
    Return the shared Supabase client instance (singleton).

    Creates the client on first call and reuses it on subsequent calls.

    Returns:
        Configured Supabase Client.

    Raises:
        ValueError: If SUPABASE_URL or SUPABASE_KEY are not configured in .env
    """

    global _client

    if _client is None:
        if not config.SUPABASE_URL or config.SUPABASE_URL == 'https://your-project.supabase.co':
            raise ValueError(
                "SUPABASE_URL is not configured. "
                "Add your Supabase project URL to .env"
            )
        if not config.SUPABASE_KEY or config.SUPABASE_KEY == 'your-supabase-anon-key':
            raise ValueError(
                "SUPABASE_KEY is not configured. "
                "Add your Supabase anon key to .env"
            )

        _client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)

    return _client
