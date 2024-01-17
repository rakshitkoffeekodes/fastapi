from fastapi import FastAPI, HTTPException, Depends, status
from sql_app import auth, models
from sql_app.database import SessionLocal, engine
from typing import Annotated
from sqlalchemy.orm import Session
from sql_app.auth import get_current_user

app = FastAPI()
app.include_router(auth.router)

models.Base.metadata.create_all(bind=engine)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@app.get("/", status_code=status.HTTP_200_OK)
def user(users: user_dependency, db: db_dependency):
    if users is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    return {"User": users}

# @app.get("/users/", response_model=list[schemas.User])
# def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
#     users = crud.get_users(db, skip=skip, limit=limit)
#     return users
#
#
# @app.get("/users/{user_id}", response_model=schemas.User)
# def read_user(user_id: int, db: Session = Depends(get_db)):
#     db_user = crud.get_user(db, user_id=user_id)
#     if db_user is None:
#         raise HTTPException(status_code=404, detail="User not found")
#     return db_user
