from sqlalchemy import Column, Integer, String, Text, Boolean, TIMESTAMP 
from sqlalchemy.sql import func

from backend.database import Base
# -------------------------
# User Model
# -------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    full_name = Column(
        String(100),
        nullable=False
    )

    username = Column(
        String(50),
        nullable=False,
        unique=True
    )

    email = Column(
        String(100),
        nullable=False,
        unique=True
    )

    phone = Column(
        String(20),
        nullable=False,
        unique=True
    )

    password_hash = Column(
        String(255),
        nullable=False
    )

    profile_picture = Column(
        String(255),
        nullable=True
    )

    about = Column(
        String(255),
        nullable=True
    )

    two_step_enabled = Column(
        Boolean,
        default=False
    )

    two_step_pin_hash = Column(
        String(255),
        nullable=True
    )

    recovery_email = Column(
        String(100),
        nullable=True
    )

    created_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )

    updated_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp()
    )


# -------------------------
# Contact Model
# -------------------------

class Contact(Base):
    __tablename__ = "contacts"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    contact_user_id = Column(
        Integer,
        nullable=False
    )

    created_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )


# -------------------------
# Conversation Model
# -------------------------

class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    conversation_type = Column(
        String(20),
        nullable=False
    )

    group_name = Column(
        String(100),
        nullable=True
    )

    group_picture = Column(
        String(255),
        nullable=True
    )

    created_by = Column(
        Integer,
        nullable=False
    )

    created_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )


# -------------------------
# Conversation Participant Model
# -------------------------

class ConversationParticipant(Base):
    __tablename__ = "conversation_participants"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    conversation_id = Column(
        Integer,
        nullable=False
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    joined_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )


# -------------------------
# Message Model
# -------------------------

class Message(Base):
    __tablename__ = "messages"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    conversation_id = Column(
        Integer,
        nullable=False
    )

    sender_id = Column(
        Integer,
        nullable=False
    )

    message_text = Column(
        Text,
        nullable=False
    )
    attachment_url = Column(
        String(500),
        nullable=True
    )

    attachment_type = Column(
        String(30),
        nullable=True
    )

    attachment_name = Column(
        String(255),
        nullable=True
    )

    sent_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )


# -------------------------
# Message Status Model
# -------------------------

class MessageStatus(Base):
    __tablename__ = "message_status"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    message_id = Column(
        Integer,
        nullable=False
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    status = Column(
        String(20),
        nullable=False,
        default="sent"
    )

    updated_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp()
    )


# -------------------------
# Notification Model
# -------------------------

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    notification_type = Column(
        String(30),
        nullable=False
    )

    title = Column(
        String(150),
        nullable=False
    )

    notification_text = Column(
        Text,
        nullable=False
    )

    is_read = Column(
        Boolean,
        default=False
    )

    created_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )


# -------------------------
# Status Model
# -------------------------

class Status(Base):
    __tablename__ = "statuses"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    status_text = Column(
        Text,
        nullable=True
    )

    media_url = Column(
        String(255),
        nullable=True
    )

    created_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )

    expires_at = Column(
        TIMESTAMP,
        nullable=True
    )


# -------------------------
# Call Model
# -------------------------

class Call(Base):
    __tablename__ = "calls"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    caller_id = Column(
        Integer,
        nullable=False
    )

    receiver_id = Column(
        Integer,
        nullable=False
    )

    call_type = Column(
        String(20),
        nullable=False
    )

    call_status = Column(
        String(20),
        nullable=False
    )

    started_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )

    ended_at = Column(
        TIMESTAMP,
        nullable=True
    )


# -------------------------
# User Settings Model
# -------------------------

class UserSettings(Base):
    __tablename__ = "user_settings"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    user_id = Column(
        Integer,
        nullable=False,
        unique=True
    )

    theme = Column(
        String(20),
        nullable=False,
        default="light"
    )

    font_size = Column(
        String(20),
        nullable=False,
        default="medium"
    )

    enter_to_send = Column(
        Boolean,
        default=True
    )

    auto_download_media = Column(
        Boolean,
        default=True
    )

    message_notifications = Column(
        Boolean,
        default=True
    )

    group_notifications = Column(
        Boolean,
        default=True
    )

    notification_sound = Column(
        Boolean,
        default=True
    )

    vibration = Column(
        Boolean,
        default=True
    )

    safety_alerts = Column(
        Boolean,
        default=True
    )

    threat_detection_alerts = Column(
        Boolean,
        default=True
    )


# -------------------------
# Support Request Model
# -------------------------

class SupportRequest(Base):
    __tablename__ = "support_requests"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    user_id = Column(
        Integer,
        nullable=False
    )

    request_type = Column(
        String(30),
        nullable=False
    )

    subject = Column(
        String(150),
        nullable=False
    )

    message = Column(
        Text,
        nullable=False
    )

    status = Column(
        String(20),
        nullable=False,
        default="open"
    )

    created_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )

    updated_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp()
    )
    # -------------------------
# Threat Model
# -------------------------

class Threat(Base):
    __tablename__ = "threats"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    message_id = Column(
        Integer,
        nullable=False
    )

    threat_type = Column(
        String(30),
        nullable=False
    )

    risk_level = Column(
        String(20),
        nullable=False
    )

    confidence = Column(
        String(10),
        nullable=True
    )

    detected_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )
    
# -------------------------
# Report Model
# -------------------------

class Report(Base):
    __tablename__ = "reports"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
        autoincrement=True
    )

    user_id = Column(
        Integer,
        nullable=True
    )

    issue_type = Column(
        String(100),
        nullable=False
    )

    description = Column(
        Text,
        nullable=False
    )

    status = Column(
        String(20),
        nullable=False,
        default="open"
    )

    created_at = Column(
        TIMESTAMP,
        server_default=func.current_timestamp()
    )
