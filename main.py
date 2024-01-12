from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jwt import DecodeError

import jwt

app = FastAPI(
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

SECRET_KEY = "123890"
ALGORITHM = "TheBeginning"

authentication_scheme = OAuth2PasswordBearer(tokenUrl="token")

def generate_jwt_token(username: str, role: str):
    data = {"sub": username, "role": role}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_from_token(token: str = Depends(authentication_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        return {"username": username, "role": role}
    except DecodeError:
        raise credentials_exception

def check_admin_role(current_user: dict = Depends(get_current_user_from_token)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")
    return current_user

def check_moderator_role(current_user: dict = Depends(get_current_user_from_token)):
    if current_user["role"] != "moderator":
        raise HTTPException(status_code=403, detail="Permission denied")
    return current_user

def check_user_role(current_user: dict = Depends(get_current_user_from_token)):
    if current_user["role"] != "user":
        raise HTTPException(status_code=403, detail="Permission denied")
    return current_user

@app.get("/users/me", response_model=dict)
async def read_users_me(current_user: dict = Depends(get_current_user_from_token)):
    return current_user

@app.get("/admin", response_model=dict, dependencies=[Depends(check_admin_role)])
async def admin_route():
    return {"message": "Welcome, Admin!"}

@app.get("/moderator", response_model=dict, dependencies=[Depends(check_moderator_role)])
async def moderator_route():
    return {"message": "Welcome, Moderator!"}

@app.get("/user", response_model=dict, dependencies=[Depends(check_user_role)])
async def user_route():
    return {"message": "Welcome, User!"}