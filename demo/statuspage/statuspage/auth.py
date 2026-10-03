"""Admin session tokens."""
import time

import jwt

SECRET = "change-me"


def issue_admin_token(user: str, ttl: int = 3600) -> str:
    token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
    return token.decode("utf-8")


def verify_admin_token(token: str) -> str:
    claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    return claims["sub"]
