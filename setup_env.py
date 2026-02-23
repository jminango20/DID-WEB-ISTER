"""
Setup script for PythonAnywhere deployment.
Run once: python setup_env.py
"""

print("=== Configuración del entorno ===\n")

supabase_url = input("SUPABASE_URL: ").strip()
supabase_key = input("SUPABASE_KEY: ").strip()
database_url = input("DATABASE_URL: ").strip()

username = input("Usuario de PythonAnywhere (ej: jminango): ").strip()

env_content = f"""FLASK_SECRET_KEY=ister-secret-key-2026-did-web
FLASK_ENV=production
FLASK_DEBUG=False
SUPABASE_URL={supabase_url}
SUPABASE_KEY={supabase_key}
DATABASE_URL={database_url}
DID_WEB_DOMAIN={username}.pythonanywhere.com
DID_METHOD=did:web:{username}.pythonanywhere.com
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
PRIVATE_KEY_PATH=keys/private_key.pem
PUBLIC_KEY_PATH=keys/public_key.pem
"""

with open('.env', 'w') as f:
    f.write(env_content)

print("\n.env creado correctamente.")
print(f"Dominio: https://{username}.pythonanywhere.com")
