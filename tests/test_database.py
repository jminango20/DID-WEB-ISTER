"""
Tests for Supabase database connection.

Run with:
    pytest tests/test_database.py -v

These tests require SUPABASE_URL and SUPABASE_KEY set in .env.
They make real network requests to your Supabase project.
"""

import pytest
from unittest.mock import patch

from utils.database import get_supabase_client


class TestSupabaseClientConfig:

    def test_raises_if_url_not_configured(self):
        """get_supabase_client must raise if SUPABASE_URL is placeholder."""
        import utils.database as db_module
        original = db_module._client
        db_module._client = None  # reset singleton

        with patch('utils.database.config') as mock_config:
            mock_config.SUPABASE_URL = 'https://your-project.supabase.co'
            mock_config.SUPABASE_KEY = 'some-key'
            with pytest.raises(ValueError, match="SUPABASE_URL"):
                get_supabase_client()

        db_module._client = original

    def test_raises_if_key_not_configured(self):
        """get_supabase_client must raise if SUPABASE_KEY is placeholder."""
        import utils.database as db_module
        original = db_module._client
        db_module._client = None

        with patch('utils.database.config') as mock_config:
            mock_config.SUPABASE_URL = 'https://real-project.supabase.co'
            mock_config.SUPABASE_KEY = 'your-supabase-anon-key'
            with pytest.raises(ValueError, match="SUPABASE_KEY"):
                get_supabase_client()

        db_module._client = original


class TestSupabaseConnection:

    def test_connection_and_credentials_table(self):
        """
        Test live connection to Supabase and that the credentials table exists.

        SKIP: Run only after SUPABASE_URL and SUPABASE_KEY are set in .env
        and the SQL schema has been applied.
        """
        import utils.database as db_module
        db_module._client = None  # reset to force fresh client

        try:
            client = get_supabase_client()
        except ValueError as e:
            pytest.skip(f"Supabase not configured yet: {e}")

        # Query the credentials table - should return an empty list, not an error
        from postgrest.exceptions import APIError
        try:
            result = client.table('credentials').select('id').limit(1).execute()
            assert result.data is not None, "Expected data key in response"
        except APIError as e:
            if 'PGRST205' in str(e) or 'schema cache' in str(e):
                pytest.fail(
                    "Connected to Supabase but 'credentials' table not found. "
                    "Run the SQL schema from PLAN.md in the Supabase SQL Editor."
                )
            raise

    def test_singleton_returns_same_instance(self):
        """get_supabase_client must return the same object on repeated calls."""
        import utils.database as db_module
        if db_module._client is None:
            try:
                get_supabase_client()
            except ValueError:
                pytest.skip("Supabase not configured yet")

        client1 = get_supabase_client()
        client2 = get_supabase_client()
        assert client1 is client2
