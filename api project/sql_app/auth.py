from datetime import timedelta, datetime, timezone
from typing import Annotated, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from sql_app.database import SessionLocal
from sql_app.models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from fastapi.responses import JSONResponse
from fastapi_permissions import (
    Allow,
    Authenticated,
    Deny,
    Everyone,
    configure_permissions,
    list_permissions,
)

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

SECRET_KEY = '197b2c37c391bed93fe80344fe73b806947a65e36206e05a1a23c2fa12702fe3'
REFRESH_SECRET_KEY = 'GEbRxB93fe80344fe73b806947a65e36206eNedinXbL'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = 'User'
    permissions: list[str] = ['User:read', 'Admin:read', 'Admin:create', 'Admin:update', 'Admin:delete']


class Token(BaseModel):
    access_token: str
    token_type: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


@router.post("/", status_code=status.HTTP_200_OK)
def create_user(db: db_dependency, username: str = Form(), email: str = Form(), password: str = Form(),
                role: str = Form()):
    check = db.query(Users).filter(Users.username == username, Users.email == email).first()
    if check:
        return JSONResponse({'message': 'user already exist'})
    create_user_model = Users(
        username=username,
        email=email,
        hash_password=password,
        role=role,
    )
    db.add(create_user_model)
    db.commit()
    return JSONResponse({'message': 'User register successfully.'})


@router.post("/token", response_model=Token)
def login_for_access_token(email: str = Form(), password: str = Form(), db: Session = Depends(get_db)):
    user = authenticate_user(email, password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='could not validate user')
    access_token = create_access_token(user.email, user.id)
    refresh_token = create_refresh_token(user.email, user.id)
    return JSONResponse({'access token': access_token, 'refresh token': refresh_token, 'token_type': 'bearer'})


def authenticate_user(email: str, password: str, db: Session):
    user = db.query(Users).filter(Users.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='email not match')
    if not password == user.hash_password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='password not match')
    return user


def create_access_token(email: str, user_id: int):
    encode = {'sub': email, 'id': user_id}
    expire = datetime.now(timezone.utc) + timedelta(days=1)
    encode.update({'exp': expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(email: str, user_id: int):
    to_encode = {'sub': email, 'id': user_id}
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    to_encode.update({'exp': expire})
    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: Annotated[str, Depends(oauth2_bearer)], db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get('sub')
        user_id: int = payload.get('id')
        if email is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate User.')
        user = db.query(Users).filter(Users.email == email).first()
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate Token.')


class PermissionChecker:
    def __init__(self, required_permissions: list[str]) -> None:
        self.required_permissions = required_permissions

    def __call__(self, user_data: dict = Depends(get_current_user)) -> bool:
        if user_data.permissions is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Permissions not found'
            )

        for r_perm in self.required_permissions:
            if r_perm not in user_data.permissions:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='Not a Permissions'
                )
        return user_data


@router.get('/data')
async def get_data(user_data: Optional[dict] = Depends(PermissionChecker(required_permissions=['User:read']))):
    if user_data.role != 'User':
        return JSONResponse({'message': 'not a permissions'})
    if user_data is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    return JSONResponse({'User Username': user_data.username, 'User email': user_data.email, 'User Role': user_data.role})
