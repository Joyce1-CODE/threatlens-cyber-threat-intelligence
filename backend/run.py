import uvicorn
import os
import sys
import socket

# Ensure backend root is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

if __name__ == "__main__":
    env_port = int(os.environ.get("PORT", 0))
    if env_port > 0:
        port = env_port
    else:
        # Default to 8000, fallback to 8001 if 8000 is occupied
        port = 8001 if is_port_in_use(8000) else 8000

    host = os.environ.get("HOST", "0.0.0.0" if env_port > 0 else "127.0.0.1")
    reload = os.environ.get("APP_ENV", "development").lower() != "production"

    print(f"[*] Starting ThreatLens AI Backend on http://{host}:{port}")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )
