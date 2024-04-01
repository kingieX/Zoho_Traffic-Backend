from sqlalchemy import Boolean, Column, ForeignKey, Integer, String,DateTime,Float
from sqlalchemy.orm import relationship
from datetime import datetime
import database


class User(database.Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    fullname = Column(String, nullable=True)
    role = Column(String,nullable=False)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    createdAt = Column(DateTime, nullable=False, default=datetime.utcnow)
    updatedAt = Column(DateTime, nullable=False, default=datetime.utcnow)

    # One-to-One relationship with PreferenceSetting
    preference_setting = relationship("PreferenceSetting", uselist=False, back_populates="user")

    # One-to-Many relationship with TrafficResult
    traffic_results = relationship("TrafficResult", back_populates="user")

    # One-to-Many relationship with IncidentReport
    incidence_report = relationship("IncidenceReport", back_populates="user")
    
    # One-to-Many relationship with FeedbackReports
    feedback_report = relationship("FeedbackReports", back_populates="user")
    
    #One-to-Many relationship with FeedbackReports
    token = relationship("Token", back_populates="user")
    
class Token(database.Base):
    __tablename__ = "token"
    user_id = Column(Integer, ForeignKey("users.id"))
    access_token = Column(String(450), primary_key=True)
    refresh_token = Column(String(450), nullable=False)
    status = Column(Boolean)
    created_date = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="token")


class PreferenceSetting(database.Base):

    __tablename__ = "preferences"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    theme = Column(String)
    notification = Column(Boolean)
    language_preference = Column(String)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # One-to-One relationship with User
    user = relationship("User", back_populates="preference_setting")


class IncidenceReport(database.Base):

    __tablename__ = "incidence_report"

    id = Column(Integer, primary_key=True)
    incidence_type = Column(String)
    location = Column(String)
    severity = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    # Many-to-One relationship with User
    user = relationship("User", back_populates="incidence_report")
    # One-to-Many relationship with FeedbackReports
    feedback_report = relationship("FeedbackReports", back_populates="incidence_report")


class FeedbackReports(database.Base):
    __tablename__ = "feedback_report"

    id = Column(Integer, primary_key=True, index=True)
    currenttimestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    feedback = Column(String)
    report_type = Column(String)
    report_data_path = Column(String)
    # Foreign key constraint for incidence_report
    incidence_report_id = Column(Integer, ForeignKey("incidence_report.id"))
    # Many-to-One relationship with IncidenceReport
    incidence_report = relationship("IncidenceReport", back_populates="feedback_report")
    #Many-to-One relationship with User
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="feedback_report")

class TrafficResult(database.Base):

    __tablename__ = "traffic_results"

    id = Column(Integer, primary_key=True, index=True)
    latitude = Column(Float)
    longitude = Column(Float)
    speed = Column(Float)
    direction = Column(Float)
    acceleration = Column(Float)
    traffic_condition = Column(String)
    road_condition = Column(String)
    weather_condition = Column(String)
    event_type = Column(String)
    is_emergency_vehicle = Column(Boolean)
    additional_info = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Many-to-One relationship with User
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="traffic_results")


class WeatherDatat(database.Base):
    __tablename__ = "weather_data"

    temperature = Column(Float)
    humidity = Column(Float)
    wind_speed = Column(Float)
    wind_direction = Column(String)
    location = Column(String)
    id = Column(Integer, primary_key=True, index=True)

