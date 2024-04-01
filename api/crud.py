from typing import List
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
import jwt
from jwt.exceptions import DecodeError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from pydantic import EmailStr
import  models, schemas, utils, config  # Update 'app' with the actual package/module name

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login", scheme_name="JWT")

def get_user(db: Session, user_id: int) -> schemas.UserOut:
    user = db.query(models.User).filter(models.User.id == user_id).first()

    if user:
        user_out = schemas.UserOut(
            id=user.id,
            username=user.username,
            email=user.email,
            fullname=user.fullname,
            role=user.role,
            is_active=user.is_active,
            # Add other fields as needed
        )
        return user_out
    else:
        raise HTTPException(status_code=404, detail="User not found")

def get_user_by_username(db: Session, username: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if user:
        return schemas.UserOut.from_orm(user)
    else:
        raise HTTPException(status_code=404, detail="User not found")

def get_user_by_email(db: Session, email: EmailStr) -> schemas.User:
    user = db.query(models.User).filter(models.User.email == email).first()
    if user:
        return schemas.User.from_orm(user)
    else:
        raise HTTPException(status_code=404, detail="User not found")

def delete_user(db: Session, user_id: int):
    user = db.query(models.User).filter(models.User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found",
        )

    db.delete(user)
    db.commit()

    return {"status": "success", "message": f"User with id {user_id} deleted"}

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user:
        return False
    if not utils.verify_password(password, user.password):
        return False
    return user

def get_users(db: Session, skip: int = 0, limit: int = 100):
    users = db.query(models.User).offset(skip).limit(limit).all()
    return [schemas.UserOut.from_orm(user) for user in users]

def get_current_user(db: Session, token: str = Depends(oauth2_scheme)) -> schemas.UserOut:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.settings.jwt_secret_key, algorithms=[config.settings.algorithm])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = schemas.TokenData(user_id=user_id)
    except DecodeError:
        raise credentials_exception
    user = get_user(db, user_id=token_data.user_id)
    if user is None:
        raise credentials_exception
    return user

def get_current_active_user(current_user: schemas.UserOut = Depends(get_current_user)):
    if current_user.is_active == 'disabled':
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def cleanup_expired_tokens(db: Session):
    old_tokens = db.query(models.Token).filter(models.Token.created_date < datetime.utcnow() - timedelta(days=1))
    old_tokens.delete()
    db.commit()

def create_incidence_report(db: Session, report: schemas.IncidenceReportCreate) -> models.IncidenceReport:
    db_report = models.IncidenceReport(**report.dict(), created_at=datetime.utcnow())
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report

def read_incidence_report(db: Session, report_id: int) -> models.IncidenceReport:
    return db.query(models.IncidenceReport).filter(models.IncidenceReport.id == report_id).first()

def update_incidence_report(db: Session, report_id: int, report: schemas.IncidenceReportCreate):
    existing_report = db.query(models.IncidenceReport).filter(models.IncidenceReport.id == report_id).first()

    if existing_report is None:
        return None

    # Update the attributes of the existing report
    for key, value in report.dict().items():
        setattr(existing_report, key, value)

    db.commit()
    db.refresh(existing_report)

    return existing_report

def delete_incidence_report(db: Session, id: int):
    incidence_report = db.query(models.IncidenceReport).filter(models.IncidenceReport.id == id).first()

    if incidence_report:
        db.delete(incidence_report)
        db.commit()
        return incidence_report
    else:
        return None

def get_traffic_results_by_user(db: Session, user_id: int) -> List[models.TrafficResult]:
    traffic_results = db.query(models.TrafficResult).filter(models.TrafficResult.user_id == user_id).all()
    return traffic_results

def get_traffic_result(db: Session, traffic_result_id: int):
    return db.query(models.TrafficResult).filter(models.TrafficResult.id == traffic_result_id).first()

def create_feedback_report(db: Session, report: schemas.FeedbackReportsCreate):
    db_report = models.FeedbackReports(**report.dict())
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report

def get_feedback_reports_by_user(db: Session, user_id: int):
    return db.query(models.FeedbackReports).filter(models.FeedbackReports.user_id == user_id).all()
 
def get_feedback_report(db: Session, report_id: int) -> models.FeedbackReports:
    return db.query(models.FeedbackReports).filter(models.FeedbackReports.id == report_id).first()

def get_all_feedback_report(db: Session, report_id: int) -> models.FeedbackReports:
    return db.query(models.FeedbackReports).filter(models.FeedbackReports.id == report_id).all()
    

