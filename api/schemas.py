from pydantic import ConfigDict, BaseModel, EmailStr
from datetime import datetime
from typing import List, Optional

class Token(BaseModel):
    access_token: str
    refresh_token: str
    user_id: int

class TokenData(BaseModel):
    user_id: int
    access_token: str
    refresh_token: str
    status: bool
    created_date: datetime

class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    fullname: Optional[str] = None
    role:str
    is_active: Optional[bool] = None

class User(UserOut):
    password: str
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)
     

class UserCreate(BaseModel):
    username: str
    fullname: Optional[str] = None
    role:str
    email: EmailStr
    password: str
    is_active: Optional[bool] = None
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None

class UserIn(BaseModel):
    email: EmailStr
    password: str

class UserInDB(User):
    hashed_password: str

class ChangePassword(BaseModel):
    email: EmailStr
    old_password: str
    new_password: str

class PreferenceSettingBase(BaseModel):
    theme: str
    notification: bool
    language_preference: str

class PreferenceSettingCreate(PreferenceSettingBase):
    user_id: int

class PreferenceSetting(PreferenceSettingBase):
    id: int
    created_at: datetime
    user_id: int

class TrafficResultBase(BaseModel):
    latitude: float
    longitude: float
    speed: float
    direction: float
    acceleration: float
    traffic_condition: str
    road_condition: str
    weather_condition: str
    event_type: str
    is_emergency_vehicle: bool
    additional_info: str

class TrafficResultCreate(TrafficResultBase):
    pass

class TrafficResult(TrafficResultBase):
    id: int
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class FeedbackReportsBase(BaseModel):
    currenttimestamp: datetime
    user_id: int
    feedback: str
    incidence_report_id: int
    report_type: str
    report_data_path: str

class FeedbackReportsCreate(FeedbackReportsBase):
    pass

class FeedbackReports(FeedbackReportsBase):
    id: int
    user: UserOut
    incidence_report_id: int
    model_config = ConfigDict(from_attributes=True)


class WeatherData(BaseModel):
    temperature: float
    humidity: float
    wind_speed: float
    wind_direction: str
    location: str

class WeatherDataCreate(WeatherData):
    pass


class IncidenceReportBase(BaseModel):
    incidence_type: str
    location: str
    severity: str
    user_id: int

class IncidenceReportCreate(IncidenceReportBase):
    pass

class IncidenceReport(IncidenceReportBase):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)