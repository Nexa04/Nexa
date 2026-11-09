import secrets
import time
from datetime import datetime
from fileinput import filename
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
class ProblemReport(BaseModel):
    issue_type: str
    description: str
from sqlalchemy.orm import Session
from fastapi import UploadFile, File
import os
import smtplib
from email.message import EmailMessage
import uuid
from fastapi.staticfiles import StaticFiles
import bcrypt
class CreateGroupRequest(BaseModel):
    group_name: str
    member_ids: list[int]
from backend.models import (
    User,
    Contact,
    Conversation,
    ConversationParticipant,
    Message,
    MessageStatus,
    Notification,
    Status,
    Call,
    UserSettings,
    SupportRequest,
    Threat,
    Report
)
from backend.auth import (
    create_access_token,
    get_current_user
)

from backend.database import engine, Base, get_db
from ai.threat_detector import analyze_message
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
# =========================
# Phone OTP Storage
# =========================

phone_otp_storage = {}
# =========================
# Email Configuration
# =========================

REPORT_EMAIL = "nexa0427@gmail.com"

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
# =========================
# Upload Directory
# =========================

UPLOAD_DIR = "backend/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount(
    "/uploads",
    StaticFiles(directory="backend/uploads"),
    name="uploads"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Create database tables if they don't exist
Base.metadata.create_all(bind=engine)


# -------------------------
# Register Request
# -------------------------

class RegisterRequest(BaseModel):
    full_name: str
    username: str
    email: str
    phone: str
    password: str


# -------------------------
# Login Request
# -------------------------

class LoginRequest(BaseModel):
    phone: str
    password: str


# -------------------------
# Update Profile Request
# -------------------------
class UpdateProfileRequest(BaseModel):
    full_name: str | None = None
    username: str | None = None
    email: str | None = None
    about: str | None = None
    profile_picture: str | None = None


# -------------------------
# Create Conversation Request
# -------------------------

class CreateConversationRequest(BaseModel):
    user_id: int

# -------------------------
# Send Message Request
# -------------------------

class SendMessageRequest(BaseModel):
    message_text: str
# -------------------------
# Update Message Status Request
# -------------------------

class UpdateMessageStatusRequest(BaseModel):
    status: str
# -------------------------
# Create Status Request
# -------------------------

class CreateStatusRequest(BaseModel):
    status_text: str | None = None
    media_url: str | None = None

# -------------------------
# Home
# -------------------------

@app.get("/")
def root():
    return {"message": "Nexa Backend is running"}


# -------------------------
# Test Database
# -------------------------

@app.get("/test-db")
def test_db():

    with engine.connect():
        return {
            "message": "Database connection successful"
        }


# -------------------------
# Register
# -------------------------

@app.post("/register")
def register(
    user_data: RegisterRequest,
    db: Session = Depends(get_db)
):

    # Check username
    existing_username = db.query(User).filter(
        User.username == user_data.username
    ).first()

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    # Check email
    existing_email = db.query(User).filter(
        User.email == user_data.email
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    # Check phone
    existing_phone = db.query(User).filter(
        User.phone == user_data.phone
    ).first()

    if existing_phone:
        raise HTTPException(
            status_code=400,
            detail="Phone number already exists"
        )

    # Hash password
    password_hash = bcrypt.hashpw(
        user_data.password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # Create user
    new_user = User(
        full_name=user_data.full_name,
        username=user_data.username,
        email=user_data.email,
        phone=user_data.phone,
        password_hash=password_hash
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "Account created successfully",
        "user_id": new_user.id,
        "username": new_user.username
    }


# -------------------------
# Login
# -------------------------

@app.post("/login")
def login(
    user_data: LoginRequest,
    db: Session = Depends(get_db)
):

    # Find user by phone
    user = db.query(User).filter(
        User.phone == user_data.phone
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid phone number or password"
        )

    # Check password
    password_correct = bcrypt.checkpw(
        user_data.password.encode("utf-8"),
        user.password_hash.encode("utf-8")
    )

    if not password_correct:
        raise HTTPException(
            status_code=401,
            detail="Invalid phone number or password"
        )

    # Create JWT
    access_token = create_access_token(user.id)

    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "full_name": user.full_name
    }


# -------------------------
# My Profile
# -------------------------

@app.get("/me")
def get_my_profile(
    current_user: User = Depends(get_current_user)
):

    return {
        "user_id": current_user.id,
        "full_name": current_user.full_name,
        "username": current_user.username,
        "phone": current_user.phone,
        "email": current_user.email,
        "profile_picture": current_user.profile_picture,
        "about": current_user.about
    }


# -------------------------
# Update My Profile
# -------------------------

@app.put("/users/me")
def update_my_profile(
    user_data: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Check username
    if user_data.username is not None:

        existing_username = db.query(User).filter(
            User.username == user_data.username,
            User.id != current_user.id
        ).first()

        if existing_username:
            raise HTTPException(
                status_code=400,
                detail="Username already exists"
            )

        current_user.username = user_data.username
    if user_data.email is not None:
        existing_email = db.query(User).filter(
        User.email == user_data.email,
        User.id != current_user.id
             ).first()

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    current_user.email = user_data.email
    if user_data.email is not None:
         current_user.email = user_data.email
    # Update full name
    if user_data.full_name is not None:
        current_user.full_name = user_data.full_name

    # Update about
    if user_data.about is not None:
        current_user.about = user_data.about

    # Update profile picture
    if user_data.profile_picture is not None:
        current_user.profile_picture = user_data.profile_picture

    db.commit()
    db.refresh(current_user)

    return {
        "message": "Profile updated successfully",
        "user_id": current_user.id,
        "full_name": current_user.full_name,
        "username": current_user.username,
        "about": current_user.about,
        "profile_picture": current_user.profile_picture,
        "email": current_user.email
    }

# -------------------------
# Get My Profile
# -------------------------

@app.get("/users/me")
def get_my_profile(
    current_user: User = Depends(get_current_user)
):

    return {
        "user_id": current_user.id,
        "full_name": current_user.full_name,
        "username": current_user.username,
        "email": current_user.email,
        "phone": current_user.phone,
        "profile_picture": current_user.profile_picture,
        "about": current_user.about
    }

# -------------------------
# Get User By ID
# -------------------------

@app.get("/users/{user_id}")
def get_user(
    user_id: int,
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "user_id": user.id,
        "full_name": user.full_name,
        "username": user.username,
        "phone": user.phone,
        "email": user.email,
        "profile_picture": user.profile_picture,
        "about": user.about
    }



# -------------------------
# Search User
# -------------------------

@app.get("/users/search/{username}")
# -------------------------
# Search User By Phone
# -------------------------

@app.get("/users/search-phone/{phone}")
def search_user_by_phone(
    phone: str,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.phone == phone
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "user_id": user.id,
        "full_name": user.full_name,
        "phone": user.phone,
        "profile_picture": user.profile_picture,
        "about": user.about
    }
def search_user(
    username: str,
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.username == username
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "user_id": user.id,
        "full_name": user.full_name,
        "username": user.username,
        "profile_picture": user.profile_picture,
        "about": user.about
    }


# -------------------------
# Add Contact
# -------------------------

@app.post("/contacts/{contact_user_id}")
def add_contact(
    contact_user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Cannot add yourself
    if contact_user_id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot add yourself"
        )

    # Check user
    contact_user = db.query(User).filter(
        User.id == contact_user_id
    ).first()

    if contact_user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Check existing contact
    existing_contact = db.query(Contact).filter(
        Contact.user_id == current_user.id,
        Contact.contact_user_id == contact_user_id
    ).first()

    if existing_contact:
        raise HTTPException(
            status_code=400,
            detail="Contact already exists"
        )

    # Create contact
    new_contact = Contact(
        user_id=current_user.id,
        contact_user_id=contact_user_id
    )

    db.add(new_contact)
    db.commit()
    db.refresh(new_contact)

    return {
        "message": "Contact added successfully",
        "contact_id": new_contact.id,
        "contact_user_id": contact_user.id,
        "username": contact_user.username
    }


# -------------------------
# Get My Contacts
# -------------------------

@app.get("/contacts")
def get_my_contacts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    contacts = db.query(Contact).filter(
        Contact.user_id == current_user.id
    ).all()

    result = []

    for contact in contacts:

        user = db.query(User).filter(
            User.id == contact.contact_user_id
        ).first()

        if user:
            result.append({
                "contact_id": contact.id,
                "user_id": user.id,
                "full_name": user.full_name,
                "username": user.username,
                "phone": user.phone,
                "profile_picture": user.profile_picture,
                "about": user.about
            })

    return {
        "contacts": result
    }


# -------------------------
# Delete Contact
# -------------------------

@app.delete("/contacts/{contact_user_id}")
def delete_contact(
    contact_user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    contact = db.query(Contact).filter(
        Contact.user_id == current_user.id,
        Contact.contact_user_id == contact_user_id
    ).first()

    if contact is None:
        raise HTTPException(
            status_code=404,
            detail="Contact not found"
        )

    db.delete(contact)
    db.commit()

    return {
        "message": "Contact deleted successfully"
    }


# -------------------------
# Create Conversation
# -------------------------

@app.post("/conversations")
def create_conversation(
    conversation_data: CreateConversationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Cannot create conversation with yourself
    if conversation_data.user_id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot create a conversation with yourself"
        )

    # Check other user
    other_user = db.query(User).filter(
        User.id == conversation_data.user_id
    ).first()

    if other_user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Check existing private conversations
    existing_conversations = (
        db.query(Conversation)
        .join(
            ConversationParticipant,
            Conversation.id == ConversationParticipant.conversation_id
        )
        .filter(
            Conversation.conversation_type == "private",
            ConversationParticipant.user_id == current_user.id
        )
        .all()
    )

    for conversation in existing_conversations:

        participants = db.query(
            ConversationParticipant
        ).filter(
            ConversationParticipant.conversation_id == conversation.id
        ).all()

        participant_ids = [
            participant.user_id
            for participant in participants
        ]

        if conversation_data.user_id in participant_ids:

            return {
                "message": "Conversation already exists",
                "conversation_id": conversation.id
            }

    # Create conversation
    new_conversation = Conversation(
        conversation_type="private",
        created_by=current_user.id
    )

    db.add(new_conversation)
    db.commit()
    db.refresh(new_conversation)

    # Add current user
    participant1 = ConversationParticipant(
        conversation_id=new_conversation.id,
        user_id=current_user.id
    )

    # Add other user
    participant2 = ConversationParticipant(
        conversation_id=new_conversation.id,
        user_id=conversation_data.user_id
    )

    db.add(participant1)
    db.add(participant2)

    db.commit()

    return {
        "message": "Conversation created successfully",
        "conversation_id": new_conversation.id,
        "participants": [
            current_user.id,
            conversation_data.user_id
        ]
    }
# -------------------------
# Get My Conversations
# -------------------------
@app.get("/conversations")
def get_my_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    conversations = (
        db.query(Conversation)
        .join(
            ConversationParticipant,
            Conversation.id == ConversationParticipant.conversation_id
        )
        .filter(
            ConversationParticipant.user_id == current_user.id
        )
        .all()
    )

    result = []

    for conversation in conversations:

        # =========================
        # Get Other User
        # =========================

        participants = db.query(
            ConversationParticipant
        ).filter(
            ConversationParticipant.conversation_id
            == conversation.id
        ).all()

        other_user = None

        for participant in participants:

            if participant.user_id != current_user.id:

                other_user = db.query(User).filter(
                    User.id == participant.user_id
                ).first()

                break


        # =========================
        # Get Last Message
        # =========================

        last_message = db.query(Message).filter(
            Message.conversation_id == conversation.id
        ).order_by(
            Message.sent_at.desc()
        ).first()


        last_message_text = None
        last_message_time = None

        if last_message:

            last_message_text = (
                last_message.message_text
            )

            last_message_time = (
                last_message.sent_at
            )


        # =========================
        # Count Unread Messages
        # =========================

        unread_count = 0

        messages = db.query(Message).filter(
            Message.conversation_id == conversation.id,
            Message.sender_id != current_user.id
        ).all()

        for message in messages:

            message_status = db.query(
                MessageStatus
            ).filter(
                MessageStatus.message_id == message.id,
                MessageStatus.user_id == current_user.id
            ).first()

            # No status = unread
            if message_status is None:

                unread_count += 1

            # Status exists but isn't read
            elif message_status.status != "read":

                unread_count += 1


        # =========================
        # Conversation Data
        # =========================

        conversation_data = {

    "conversation_id":
        conversation.id,

    "conversation_type":
        conversation.conversation_type,

    "created_at":
        conversation.created_at,

    "group_name":
        conversation.group_name,

    "other_user":
        None,

    "last_message":
        last_message_text,

    "last_message_time":
        last_message_time,

    "unread_count":
        unread_count
}
        

        # =========================
        # Add Other User
        # =========================

        if other_user:

            conversation_data["other_user"] = {

                "user_id":
                    other_user.id,

                "full_name":
                    other_user.full_name,

                "username":
                    other_user.username,

                "profile_picture":
                    other_user.profile_picture,

                "about":
                    other_user.about
            }
        if conversation.conversation_type == "group":

                conversation_data["group"] = {
        "group_name":
            conversation.group_name,

        "created_by":
            conversation.created_by
    }

        result.append(
            conversation_data
        )


    # =========================
    # Latest Conversation First
    # =========================

    result.sort(
        key=lambda x:
            x["last_message_time"]
            if x["last_message_time"]
            else x["created_at"],
        reverse=True
    )


    return {
        "conversations": result
    }
# -------------------------
# Send Message
# -------------------------
@app.post("/conversations/{conversation_id}/messages")
def send_message(
    conversation_id: int,
    message_data: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # =========================
    # Check Conversation
    # =========================

    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id
    ).first()

    if conversation is None:
        raise HTTPException(
            status_code=404,
            detail="Conversation not found"
        )


    # =========================
    # Check Participant
    # =========================

    participant = db.query(
        ConversationParticipant
    ).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == current_user.id
    ).first()

    if participant is None:
        raise HTTPException(
            status_code=403,
            detail="You are not a participant in this conversation"
        )


    # =========================
    # Check Empty Message
    # =========================

    if not message_data.message_text.strip():
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty"
        )


    # =========================
    # Create Message
    # =========================

    new_message = Message(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        message_text=message_data.message_text
    )

    db.add(new_message)
    db.commit()
    db.refresh(new_message)


    # =========================
    # Analyze Message Using AI
    # =========================

    analysis = analyze_message(
        new_message.message_text
    )


    # =========================
    # Save Threat Analysis
    # Only if message is not safe
    # =========================

    if analysis["risk_level"] in ["suspicious", "high_risk"]:

        new_threat = Threat(
            message_id=new_message.id,
            threat_type=analysis["threat_type"],
            risk_level=analysis["risk_level"],
            confidence=analysis["confidence"]
        )

        db.add(new_threat)


    # =========================
    # Create Safety Alert
    # Only if message is not safe
    # =========================

    if analysis["risk_level"] in ["suspicious", "high_risk"]:
        participants = db.query(
            ConversationParticipant
        ).filter(
            ConversationParticipant.conversation_id == conversation_id,
            ConversationParticipant.user_id != current_user.id
        ).all()

        for participant in participants:

            # Get notification settings
            user_settings = db.query(
                UserSettings
            ).filter(
                UserSettings.user_id == participant.user_id
            ).first()


            # Create default settings
            # if they don't exist
            if user_settings is None:

                user_settings = UserSettings(
                    user_id=participant.user_id
                )

                db.add(user_settings)
                db.flush()


            # Send alert only if enabled
            if user_settings.threat_detection_alerts:

                new_notification = Notification(
                    user_id=participant.user_id,
                    notification_type="threat_alert",
                    title="Safety Alert",
                    notification_text=(
                        f"A potentially unsafe message was detected. "
                        f"Risk level: {analysis['risk_level']}"
                    ),
                    is_read=False
                )

                db.add(new_notification)


    # =========================
    # Save Everything
    # =========================

    db.commit()


    # =========================
    # Return Result
    # =========================

    return {
        "message": "Message sent successfully",
        "message_id": new_message.id,
        "conversation_id": new_message.conversation_id,
        "sender_id": new_message.sender_id,
        "message_text": new_message.message_text,
        "sent_at": new_message.sent_at,
        "threat_analysis": analysis
    }
# -------------------------
# Get Conversation Messages
# -------------------------

@app.get("/conversations/{conversation_id}/messages")
def get_conversation_messages(
    conversation_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Check conversation
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id
    ).first()

    if conversation is None:
        raise HTTPException(
            status_code=404,
            detail="Conversation not found"
        )

    # Check if current user is a participant
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == current_user.id
    ).first()

    if participant is None:
        raise HTTPException(
            status_code=403,
            detail="You are not a participant in this conversation"
        )

    # Get messages
    messages = db.query(Message).filter(
        Message.conversation_id == conversation_id
    ).order_by(
        Message.sent_at.asc()
    ).all()

    result = []

    for message in messages:

        result.append({
    "message_id": message.id,
    "sender_id": message.sender_id,
    "message_text": message.message_text,
    "sent_at": message.sent_at,
    "attachment_url": message.attachment_url,
    "attachment_type": message.attachment_type,
    "attachment_name": message.attachment_name
})

    return {
        "conversation_id": conversation_id,
        "messages": result
    }

# -------------------------
# Upload Chat Attachment
# -------------------------

@app.post("/conversations/{conversation_id}/attachments")
async def upload_chat_attachment(
    conversation_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check conversation
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id
    ).first()

    if conversation is None:
        raise HTTPException(
            status_code=404,
            detail="Conversation not found"
        )

    # Check participant
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == current_user.id
    ).first()

    if participant is None:
        raise HTTPException(
            status_code=403,
            detail="You are not a participant in this conversation"
        )

    # Allow selected file types
    allowed_types = {
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif",
        "video/mp4",
        "application/pdf",
        "text/plain",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail="File type is not allowed"
        )

    # Limit file size to 10 MB
    max_size = 10 * 1024 * 1024
    content = await file.read(max_size + 1)

    if len(content) > max_size:
        raise HTTPException(
            status_code=413,
            detail="File size must not exceed 10 MB"
        )

    # Generate safe unique filename
    extension = os.path.splitext(file.filename or "")[1].lower()
    safe_filename = f"{uuid.uuid4().hex}{extension}"

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    with open(file_path, "wb") as output_file:
        output_file.write(content)

    # Determine attachment type
    if file.content_type.startswith("image/"):
        attachment_type = "image"
    elif file.content_type.startswith("video/"):
        attachment_type = "video"
    else:
        attachment_type = "document"

    # Create message containing attachment
    new_message = Message(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        message_text="",
        attachment_url=f"/uploads/{safe_filename}",
        attachment_type=attachment_type,
        attachment_name=file.filename
    )

    db.add(new_message)
    db.commit()
    db.refresh(new_message)

    return {
        "message": "Attachment sent successfully",
        "message_id": new_message.id,
        "conversation_id": conversation_id,
        "sender_id": current_user.id,
        "message_text": new_message.message_text,
        "attachment_url": new_message.attachment_url,
        "attachment_type": new_message.attachment_type,
        "attachment_name": new_message.attachment_name,
        "sent_at": new_message.sent_at
    }

# -------------------------
# Update Message Status
# -------------------------

@app.put("/messages/{message_id}/status")
def update_message_status(
    message_id: int,
    status_data: UpdateMessageStatusRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Check message
    message = db.query(Message).filter(
        Message.id == message_id
    ).first()

    if message is None:
        raise HTTPException(
            status_code=404,
            detail="Message not found"
        )

    # Check valid status
    valid_statuses = ["sent", "delivered", "read"]

    if status_data.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid message status"
        )

    # Check if user belongs to the conversation
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == message.conversation_id,
        ConversationParticipant.user_id == current_user.id
    ).first()

    if participant is None:
        raise HTTPException(
            status_code=403,
            detail="You are not a participant in this conversation"
        )

    # Check existing status
    message_status = db.query(MessageStatus).filter(
        MessageStatus.message_id == message_id,
        MessageStatus.user_id == current_user.id
    ).first()

    # Create status if it doesn't exist
    if message_status is None:

        message_status = MessageStatus(
            message_id=message_id,
            user_id=current_user.id,
            status=status_data.status
        )

        db.add(message_status)

    # Update existing status
    else:

        message_status.status = status_data.status

    db.commit()
    db.refresh(message_status)

    return {
        "message": "Message status updated successfully",
        "message_id": message_id,
        "user_id": current_user.id,
        "status": message_status.status
    }
# -------------------------
# Get Message Status
# -------------------------

@app.get("/messages/{message_id}/status")
def get_message_status(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Check message
    message = db.query(Message).filter(
        Message.id == message_id
    ).first()

    if message is None:
        raise HTTPException(
            status_code=404,
            detail="Message not found"
        )

    # Check if current user belongs to the conversation
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == message.conversation_id,
        ConversationParticipant.user_id == current_user.id
    ).first()

    if participant is None:
        raise HTTPException(
            status_code=403,
            detail="You are not a participant in this conversation"
        )

    # Get status of recipients
    recipient_statuses = db.query(MessageStatus).join(
        ConversationParticipant,
        MessageStatus.user_id == ConversationParticipant.user_id
    ).filter(
        MessageStatus.message_id == message_id,
        ConversationParticipant.conversation_id == message.conversation_id,
        MessageStatus.user_id != message.sender_id
    ).all()

    # Default status
    current_status = "sent"

    # Check if any recipient has read the message
    for status in recipient_statuses:

        if status.status == "read":
            current_status = "read"
            break

        elif (
            status.status == "delivered"
            and current_status == "sent"
        ):
            current_status = "delivered"

    return {
        "message_id": message_id,
        "status": current_status
    }
# -------------------------
# Create Notification Request
# -------------------------

class CreateNotificationRequest(BaseModel):
    user_id: int
    notification_type: str
    title: str
    notification_text: str


# -------------------------
# Create Notification
# -------------------------

@app.post("/notifications")
def create_notification(
    notification_data: CreateNotificationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Check if target user exists
    user = db.query(User).filter(
        User.id == notification_data.user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    # Check notification type
    valid_types = [
        "message",
        "safety_alert",
        "threat_alert"
    ]

    if notification_data.notification_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid notification type"
        )

    # Create notification
    new_notification = Notification(
        user_id=notification_data.user_id,
        notification_type=notification_data.notification_type,
        title=notification_data.title,
        notification_text=notification_data.notification_text,
        is_read=False
    )

    db.add(new_notification)
    db.commit()
    db.refresh(new_notification)

    return {
        "message": "Notification created successfully",
        "notification_id": new_notification.id,
        "user_id": new_notification.user_id,
        "notification_type": new_notification.notification_type,
        "title": new_notification.title,
        "notification_text": new_notification.notification_text,
        "is_read": new_notification.is_read
    }
    # -------------------------
# Get My Notifications
# -------------------------

@app.get("/notifications")
def get_my_notifications(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    notifications = db.query(Notification).filter(
        Notification.user_id == current_user.id
    ).order_by(
        Notification.created_at.desc()
    ).all()

    result = []

    for notification in notifications:

        result.append({
            "notification_id": notification.id,
            "notification_type": notification.notification_type,
            "title": notification.title,
            "notification_text": notification.notification_text,
            "is_read": notification.is_read,
            "created_at": notification.created_at
        })

    return {
        "notifications": result
    }
@app.put("/notifications/{notification_id}/read")
def mark_notification_as_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id
    ).first()

    if notification is None:
        raise HTTPException(
            status_code=404,
            detail="Notification not found"
        )

    notification.is_read = True

    db.commit()
    db.refresh(notification)

    return {
        "message": "Notification marked as read",
        "notification_id": notification.id,
        "is_read": notification.is_read
    }
# -------------------------
# Mark Notification As Read
# -------------------------

@app.put("/notifications/{notification_id}/read")
def mark_notification_as_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Find notification
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id
    ).first()

    if notification is None:
        raise HTTPException(
            status_code=404,
            detail="Notification not found"
        )

    # Mark as read
    notification.is_read = True

    db.commit()
    db.refresh(notification)

    return {
        "message": "Notification marked as read",
        "notification_id": notification.id,
        "is_read": notification.is_read
    }
# -------------------------
# Create Status
# -------------------------

@app.post("/statuses")
def create_status(
    status_data: CreateStatusRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Status must contain text or media
    if not status_data.status_text and not status_data.media_url:
        raise HTTPException(
            status_code=400,
            detail="Status must contain text or media"
        )

    new_status = Status(
        user_id=current_user.id,
        status_text=status_data.status_text,
        media_url=status_data.media_url
    )

    db.add(new_status)
    db.commit()
    db.refresh(new_status)

    return {
        "message": "Status created successfully",
        "status_id": new_status.id,
        "user_id": new_status.user_id,
        "status_text": new_status.status_text,
        "media_url": new_status.media_url,
        "created_at": new_status.created_at
    }
# -------------------------
# Get Statuses
# -------------------------

@app.get("/statuses")
def get_statuses(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    statuses = db.query(Status).order_by(
        Status.created_at.desc()
    ).all()

    result = []

    for status in statuses:

        user = db.query(User).filter(
            User.id == status.user_id
        ).first()

        if user:
            result.append({
                "status_id": status.id,
                "user_id": user.id,
                "full_name": user.full_name,
                "username": user.username,
                "profile_picture": user.profile_picture,
                "status_text": status.status_text,
                "media_url": status.media_url,
                "created_at": status.created_at,
                "expires_at": status.expires_at
            })

    return {
        "statuses": result
    }
    # -------------------------
# Delete Status
# -------------------------

@app.delete("/statuses/{status_id}")
def delete_status(
    status_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Find status belonging to current user
    status = db.query(Status).filter(
        Status.id == status_id,
        Status.user_id == current_user.id
    ).first()

    if status is None:
        raise HTTPException(
            status_code=404,
            detail="Status not found"
        )

    # Delete status
    db.delete(status)
    db.commit()

    return {
        "message": "Status deleted successfully",
        "status_id": status_id
    }
# -------------------------
# Start Call Request
# -------------------------

class StartCallRequest(BaseModel):
    receiver_id: int
    call_type: str
class UpdateSettingsRequest(BaseModel):
    theme: str | None = None
    font_size: str | None = None
    enter_to_send: bool | None = None
    auto_download_media: bool | None = None
    message_notifications: bool | None = None
    group_notifications: bool | None = None
    notification_sound: bool | None = None
    vibration: bool | None = None
    safety_alerts: bool | None = None
    threat_detection_alerts: bool | None = None
class CreateSupportRequest(BaseModel):
    request_type: str
    subject: str
    message: str

# -------------------------
# Start Call
# -------------------------

@app.post("/calls")
def start_call(
    call_data: StartCallRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Cannot call yourself
    if call_data.receiver_id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot call yourself"
        )

    # Check receiver
    receiver = db.query(User).filter(
        User.id == call_data.receiver_id
    ).first()

    if receiver is None:
        raise HTTPException(
            status_code=404,
            detail="Receiver not found"
        )

    # Check call type
    if call_data.call_type not in ["audio", "video"]:
        raise HTTPException(
            status_code=400,
            detail="Call type must be audio or video"
        )

    # Create call
    new_call = Call(
        caller_id=current_user.id,
        receiver_id=call_data.receiver_id,
        call_type=call_data.call_type,
        call_status="outgoing"
    )

    db.add(new_call)
    db.commit()
    db.refresh(new_call)

    return {
        "message": "Call started successfully",
        "call_id": new_call.id,
        "caller_id": new_call.caller_id,
        "receiver_id": new_call.receiver_id,
        "call_type": new_call.call_type,
        "call_status": new_call.call_status,
        "started_at": new_call.started_at
    }
# -------------------------
# End Call
# -------------------------

@app.put("/calls/{call_id}/end")
def end_call(
    call_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Find call
    call = db.query(Call).filter(
        Call.id == call_id
    ).first()

    if call is None:
        raise HTTPException(
            status_code=404,
            detail="Call not found"
        )

    # Check if current user is part of the call
    if (
        call.caller_id != current_user.id
        and call.receiver_id != current_user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="You are not part of this call"
        )

    # End call
    call.ended_at = datetime.now()
    call.call_status = "ended"

    db.commit()
    db.refresh(call)

    return {
        "message": "Call ended successfully",
        "call_id": call.id,
        "call_status": call.call_status,
        "started_at": call.started_at,
        "ended_at": call.ended_at
    }
# -------------------------
# Get My Calls
# -------------------------

@app.get("/calls")
def get_my_calls(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    calls = db.query(Call).filter(
        (Call.caller_id == current_user.id) |
        (Call.receiver_id == current_user.id)
    ).order_by(
        Call.started_at.desc()
    ).all()

    result = []

    for call in calls:

        if call.caller_id == current_user.id:
            other_user_id = call.receiver_id
            direction = "outgoing"
        else:
            other_user_id = call.caller_id
            direction = "incoming"

        other_user = db.query(User).filter(
            User.id == other_user_id
        ).first()

        if other_user:
            result.append({
                "call_id": call.id,
                "other_user_id": other_user.id,
                "other_user_name": other_user.full_name,
                "other_user_username": other_user.username,
                "call_type": call.call_type,
                "call_status": call.call_status,
                "direction": direction,
                "started_at": call.started_at,
                "ended_at": call.ended_at
            })

    return {
        "calls": result
    }
# =========================
# INCOMING CALLS
# =========================

@app.get("/calls/incoming")
def get_incoming_calls(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    calls = db.query(Call).filter(
        Call.receiver_id == current_user.id,
        Call.call_status == "outgoing",
        Call.ended_at == None
    ).order_by(
        Call.started_at.desc()
    ).all()

    result = []

    for call in calls:

        caller = db.query(User).filter(
            User.id == call.caller_id
        ).first()

        if caller:

            result.append({
                "call_id": call.id,
                "caller_id": caller.id,
                "caller_name": caller.full_name,
                "caller_username": caller.username,
                "call_type": call.call_type,
                "call_status": call.call_status,
                "started_at": call.started_at
            })

    return {
        "calls": result
    }
# -------------------------
# Create Support Request
# -------------------------

@app.post("/support")
def create_support_request(
    request: CreateSupportRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Check request type
    valid_types = [
        "account_help",
        "technical_help",
        "safety_assistance",
        "general_support"
    ]

    if request.request_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid request type"
        )

    # Create support request
    new_request = SupportRequest(
        user_id=current_user.id,
        request_type=request.request_type,
        subject=request.subject,
        message=request.message,
        status="open"
    )

    db.add(new_request)
    db.commit()
    db.refresh(new_request)

    return {
        "message": "Support request created successfully",
        "request_id": new_request.id,
        "request_type": new_request.request_type,
        "subject": new_request.subject,
        "status": new_request.status
    }
# -------------------------
# Get My Support Requests
# -------------------------

@app.get("/support")
def get_my_support_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    requests = db.query(SupportRequest).filter(
        SupportRequest.user_id == current_user.id
    ).order_by(
        SupportRequest.created_at.desc()
    ).all()

    result = []

    for support_request in requests:
        result.append({
            "request_id": support_request.id,
            "request_type": support_request.request_type,
            "subject": support_request.subject,
            "message": support_request.message,
            "status": support_request.status,
            "created_at": support_request.created_at,
            "updated_at": support_request.updated_at
        })

    return {
        "support_requests": result
    }
# -------------------------
# Get My Settings
# -------------------------

@app.get("/settings")
def get_my_settings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    settings = db.query(UserSettings).filter(
        UserSettings.user_id == current_user.id
    ).first()

    # Create default settings if they don't exist
    if settings is None:
        settings = UserSettings(
            user_id=current_user.id
        )

        db.add(settings)
        db.commit()
        db.refresh(settings)

    return {
        "user_id": settings.user_id,
        "theme": settings.theme,
        "font_size": settings.font_size,
        "enter_to_send": settings.enter_to_send,
        "auto_download_media": settings.auto_download_media,
        "message_notifications": settings.message_notifications,
        "group_notifications": settings.group_notifications,
        "notification_sound": settings.notification_sound,
        "vibration": settings.vibration,
        "safety_alerts": settings.safety_alerts,
        "threat_detection_alerts": settings.threat_detection_alerts
    }
# -------------------------
# Update My Settings
# -------------------------

@app.put("/settings")
def update_my_settings(
    settings_data: UpdateSettingsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    settings = db.query(UserSettings).filter(
        UserSettings.user_id == current_user.id
    ).first()

    # Create settings if they don't exist
    if settings is None:
        settings = UserSettings(
            user_id=current_user.id
        )
        db.add(settings)

    # Theme
    if settings_data.theme is not None:
        if settings_data.theme not in ["light", "dark"]:
            raise HTTPException(
                status_code=400,
                detail="Theme must be light or dark"
            )

        settings.theme = settings_data.theme

    # Font size
    if settings_data.font_size is not None:
        if settings_data.font_size not in ["small", "medium", "large"]:
            raise HTTPException(
                status_code=400,
                detail="Font size must be small, medium or large"
            )

        settings.font_size = settings_data.font_size

    # Other settings
    if settings_data.enter_to_send is not None:
        settings.enter_to_send = settings_data.enter_to_send

    if settings_data.auto_download_media is not None:
        settings.auto_download_media = settings_data.auto_download_media

    if settings_data.message_notifications is not None:
        settings.message_notifications = settings_data.message_notifications

    if settings_data.group_notifications is not None:
        settings.group_notifications = settings_data.group_notifications

    if settings_data.notification_sound is not None:
        settings.notification_sound = settings_data.notification_sound

    if settings_data.vibration is not None:
        settings.vibration = settings_data.vibration

    if settings_data.safety_alerts is not None:
        settings.safety_alerts = settings_data.safety_alerts

    if settings_data.threat_detection_alerts is not None:
        settings.threat_detection_alerts = settings_data.threat_detection_alerts

    db.commit()
    db.refresh(settings)

    return {
        "message": "Settings updated successfully",
        "user_id": settings.user_id,
        "theme": settings.theme,
        "font_size": settings.font_size,
        "enter_to_send": settings.enter_to_send,
        "auto_download_media": settings.auto_download_media,
        "message_notifications": settings.message_notifications,
        "group_notifications": settings.group_notifications,
        "notification_sound": settings.notification_sound,
        "vibration": settings.vibration,
        "safety_alerts": settings.safety_alerts,
        "threat_detection_alerts": settings.threat_detection_alerts
    }
# -------------------------
# Analyze Message Threat
# -------------------------

@app.post("/messages/{message_id}/analyze")
def analyze_message_threat(
    message_id: int,
    threat_type: str,
    risk_level: str,
    confidence: float | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Check message
    message = db.query(Message).filter(
        Message.id == message_id
    ).first()

    if message is None:
        raise HTTPException(
            status_code=404,
            detail="Message not found"
        )

    # Check if user belongs to the conversation
    participant = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == message.conversation_id,
        ConversationParticipant.user_id == current_user.id
    ).first()

    if participant is None:
        raise HTTPException(
            status_code=403,
            detail="You are not a participant in this conversation"
        )

    # Validate threat type
    valid_threat_types = [
        "blackmail",
        "grooming",
        "threat",
        "harassment"
    ]

    if threat_type not in valid_threat_types:
        raise HTTPException(
            status_code=400,
            detail="Invalid threat type"
        )

    # Validate risk level
    valid_risk_levels = [
        "safe",
        "suspicious",
        "high_risk"
    ]

    if risk_level not in valid_risk_levels:
        raise HTTPException(
            status_code=400,
            detail="Invalid risk level"
        )

    # Validate confidence
    if confidence is not None:
        if confidence < 0 or confidence > 100:
            raise HTTPException(
                status_code=400,
                detail="Confidence must be between 0 and 100"
            )

    # Create threat record
    new_threat = Threat(
        message_id=message_id,
        threat_type=threat_type,
        risk_level=risk_level,
        confidence=str(confidence) if confidence is not None else None
    )

    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)

    return {
        "message": "Threat analysis saved successfully",
        "threat_id": new_threat.id,
        "message_id": message_id,
        "threat_type": new_threat.threat_type,
        "risk_level": new_threat.risk_level,
        "confidence": confidence
    }
# -------------------------
# Get My Threats
# -------------------------

@app.get("/threats")
def get_my_threats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    threats = (
        db.query(Threat)
        .join(Message, Threat.message_id == Message.id)
        .filter(Message.sender_id == current_user.id)
        .order_by(Threat.detected_at.desc())
        .all()
    )

    result = []

    for threat in threats:
        result.append({
            "threat_id": threat.id,
            "message_id": threat.message_id,
            "threat_type": threat.threat_type,
            "risk_level": threat.risk_level,
            "confidence": threat.confidence,
            "detected_at": threat.detected_at
        })

    return {
        "threats": result
    }
@app.post("/groups")
def create_group(
    group_data: CreateGroupRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Check group name
    if not group_data.group_name.strip():
        raise HTTPException(
            status_code=400,
            detail="Group name cannot be empty"
        )

    # Check members
    if not group_data.member_ids:
        raise HTTPException(
            status_code=400,
            detail="At least one member is required"
        )

    # Remove duplicate member IDs
    member_ids = list(set(group_data.member_ids))

    # Make sure current user is included
    if current_user.id not in member_ids:
        member_ids.append(current_user.id)

    # Check that all users exist
    users = db.query(User).filter(
        User.id.in_(member_ids)
    ).all()

    if len(users) != len(member_ids):
        raise HTTPException(
            status_code=404,
            detail="One or more users not found"
        )

    # Create conversation
    new_group = Conversation(
        conversation_type="group",
        group_name=group_data.group_name.strip(),
        created_by=current_user.id
    )

    db.add(new_group)
    db.commit()
    db.refresh(new_group)

    # Add participants
    for user_id in member_ids:

        participant = ConversationParticipant(
            conversation_id=new_group.id,
            user_id=user_id
        )

        db.add(participant)

    db.commit()

    return {
        "message": "Group created successfully",
        "conversation_id": new_group.id,
        "group_name": new_group.group_name,
        "created_by": new_group.created_by,
        "member_ids": member_ids
    }
@app.get("/users/search-all/{search}")
def search_users(
    search: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    users = db.query(User).filter(
        User.id != current_user.id,
        (
            User.full_name.ilike(f"%{search}%")
            | User.username.ilike(f"%{search}%")
            | User.phone.ilike(f"%{search}%")
        )
    ).all()

    return {
        "users": [
            {
                "user_id": user.id,
                "full_name": user.full_name,
                "username": user.username,
                "phone": user.phone,
                "profile_picture": user.profile_picture,
                "about": user.about
            }
            for user in users
        ]
    }
# -------------------------
# Get Group Information
# -------------------------
@app.get("/groups/{conversation_id}")
def get_group_info(
    conversation_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Find group
    group = db.query(Conversation).filter(
        Conversation.id == conversation_id,
        Conversation.conversation_type == "group"
    ).first()

    if group is None:
        raise HTTPException(
            status_code=404,
            detail="Group not found"
        )

    # Check if current user is a member
    current_participant = db.query(
        ConversationParticipant
    ).filter(
        ConversationParticipant.conversation_id == conversation_id,
        ConversationParticipant.user_id == current_user.id
    ).first()

    if current_participant is None:
        raise HTTPException(
            status_code=403,
            detail="You are not a member of this group"
        )

    # Get members
    participants = db.query(
        ConversationParticipant
    ).filter(
        ConversationParticipant.conversation_id == conversation_id
    ).all()

    members = []

    for participant in participants:

        user = db.query(User).filter(
            User.id == participant.user_id
        ).first()

        if user:

            members.append({
                "user_id": user.id,
                "full_name": user.full_name,
                "username": user.username,
                "profile_picture": user.profile_picture,
                "about": user.about,
                "is_creator":
                    user.id == group.created_by
            })

    return {
        "conversation_id": group.id,
        "group_name": group.group_name,
        "group_picture": group.group_picture,
        "created_by": group.created_by,
        "members": members
    }
@app.delete("/groups/{conversation_id}")
def delete_group(
    conversation_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(Conversation).filter(
        Conversation.id == conversation_id,
        Conversation.conversation_type == "group"
    ).first()

    if group is None:
        raise HTTPException(
            status_code=404,
            detail="Group not found"
        )

    if group.created_by != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the group creator can delete the group"
        )

    db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation_id
    ).delete(synchronize_session=False)

    db.query(Message).filter(
        Message.conversation_id == conversation_id
    ).delete(synchronize_session=False)

    db.delete(group)
    db.commit()

    return {
        "message": "Group deleted successfully"
    }
@app.post("/users/me/profile-picture")
async def upload_profile_picture(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail="Only image files are allowed"
        )

    upload_folder = "backend/uploads"

    os.makedirs(upload_folder, exist_ok=True)

    extension = os.path.splitext(file.filename)[1]

    filename = f"{uuid.uuid4()}{extension}"

    file_path = os.path.join(
        upload_folder,
        filename
    )

    image_data = await file.read()

    with open(file_path, "wb") as image_file:
        image_file.write(image_data)

    current_user.profile_picture = f"/uploads/{filename}"

    db.commit()
    db.refresh(current_user)

    return {
        "message": "Profile picture updated successfully",
        "profile_picture": current_user.profile_picture
    }
# =========================
# Get Current User Info
# =========================

@app.get("/users/me")
def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    return {
        "user_id": current_user.id,
        "full_name": current_user.full_name,
        "username": current_user.username,
        "phone": current_user.phone
    }
# =========================
# WEBRTC SIGNALING
# =========================

call_signals = {}


class WebRTCSignalRequest(BaseModel):
    call_id: int
    signal_type: str
    signal_data: dict


@app.post("/calls/signal")
def send_call_signal(
    signal_data: WebRTCSignalRequest,
    current_user: User = Depends(get_current_user)
):
    if signal_data.signal_type not in [
        "offer",
        "answer",
        "ice-candidate"
    ]:
        raise HTTPException(
            status_code=400,
            detail="Invalid signal type"
        )

    if signal_data.call_id not in call_signals:
        call_signals[signal_data.call_id] = []

    call_signals[signal_data.call_id].append({
        "user_id": current_user.id,
        "signal_type": signal_data.signal_type,
        "signal_data": signal_data.signal_data
    })

    return {
        "message": "Signal sent successfully"
    }


@app.get("/calls/{call_id}/signals")
def get_call_signals(
    call_id: int,
    current_user: User = Depends(get_current_user)
):
    signals = call_signals.get(call_id, [])

    return {
        "signals": [
            signal
            for signal in signals
            if signal["user_id"] != current_user.id
        ]
    }
# =========================
# CALL STATUS
# =========================

@app.get("/calls/{call_id}/status")
def get_call_status(
    call_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    call = db.query(Call).filter(
        Call.id == call_id
    ).first()

    if call is None:
        raise HTTPException(
            status_code=404,
            detail="Call not found"
        )

    if (
        call.caller_id != current_user.id
        and call.receiver_id != current_user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="You are not part of this call"
        )

    return {
        "call_id": call.id,
        "call_status": call.call_status,
        "started_at": call.started_at,
        "ended_at": call.ended_at
    }
    # =========================
# ANSWER CALL
# =========================

@app.put("/calls/{call_id}/answer")
def answer_call(
    call_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    call = db.query(Call).filter(
        Call.id == call_id
    ).first()

    if call is None:
        raise HTTPException(
            status_code=404,
            detail="Call not found"
        )

    if call.receiver_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the receiver can answer this call"
        )

    if call.call_status != "outgoing":
        raise HTTPException(
            status_code=400,
            detail="Call cannot be answered"
        )

    call.call_status = "answered"

    db.commit()
    db.refresh(call)

    return {
        "message": "Call answered successfully",
        "call_id": call.id,
        "call_status": call.call_status
    }


# =========================
# Report a Problem
# =========================

@app.post("/report-problem")
def report_problem(
    report: ProblemReport,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    new_report = Report(
        user_id=current_user.id,
        issue_type=report.issue_type,
        description=report.description,
        status="open"
    )

    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return {
        "message": "Report submitted successfully",
        "report_id": new_report.id,
        "user_id": new_report.user_id,
        "issue_type": new_report.issue_type,
        "description": new_report.description,
        "status": new_report.status,
        "created_at": new_report.created_at
    }

# =========================
# Get My Reports
# =========================

@app.get("/my-reports")
def get_my_reports(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    reports = db.query(Report).filter(
        Report.user_id == current_user.id
    ).order_by(
        Report.created_at.desc()
    ).all()

    result = []

    for report in reports:
        result.append({
            "report_id": report.id,
            "issue_type": report.issue_type,
            "description": report.description,
            "status": report.status,
            "created_at": report.created_at
        })

    return {
        "message": "Reports retrieved successfully",
        "reports": result
    }

# =========================
# Send Phone Verification Code
# =========================

@app.post("/phone/send-code")
def send_phone_code(
    new_phone: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    new_phone = new_phone.strip()

    # Validate phone number
    if not new_phone.isdigit() or len(new_phone) < 8:
        raise HTTPException(
            status_code=400,
            detail="Invalid phone number."
        )

    # Check if phone is already used
    existing_user = db.query(User).filter(
        User.phone == new_phone
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="This phone number is already registered."
        )

    # Generate OTP
    otp_code = str(secrets.randbelow(900000) + 100000)

    # Save OTP temporarily
    phone_otp_storage[current_user.id] = {
        "phone": new_phone,
        "code": otp_code,
        "expires_at": time.time() + 300
    }

    # Display OTP in terminal (testing only)
    print("NEXA PHONE OTP:", otp_code)

    return {
        "message": "Verification code generated successfully."
    }

# =========================
# Verify Phone OTP
# =========================

@app.post("/phone/verify-code")
def verify_phone_code(
    otp_code: str,
    current_user: User = Depends(get_current_user)
):

    # Get stored OTP
    otp_data = phone_otp_storage.get(current_user.id)

    if not otp_data:
        raise HTTPException(
            status_code=400,
            detail="No verification code found. Please request a new code."
        )

    # Check expiration
    if time.time() > otp_data["expires_at"]:
        phone_otp_storage.pop(current_user.id, None)

        raise HTTPException(
            status_code=400,
            detail="Verification code expired. Please request a new code."
        )

    # Check OTP
    if otp_code != otp_data["code"]:
        raise HTTPException(
            status_code=400,
            detail="Incorrect verification code."
        )

    # Mark OTP as verified
    otp_data["verified"] = True

    return {
        "message": "Phone number verified successfully.",
        "verified": True
    }

# =========================
# Change Phone Number
# =========================

@app.put("/phone/change")
def change_phone_number(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Get OTP data
    otp_data = phone_otp_storage.get(current_user.id)

    if not otp_data:
        raise HTTPException(
            status_code=400,
            detail="Please verify your new phone number first."
        )

    # Check verification
    if not otp_data.get("verified"):
        raise HTTPException(
            status_code=400,
            detail="Phone number is not verified."
        )

    # Check expiration again
    if time.time() > otp_data["expires_at"]:
        phone_otp_storage.pop(current_user.id, None)

        raise HTTPException(
            status_code=400,
            detail="Verification expired. Please request a new code."
        )

    new_phone = otp_data["phone"]

    # Check phone availability again
    existing_user = db.query(User).filter(
        User.phone == new_phone,
        User.id != current_user.id
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="This phone number is already registered."
        )

    # Update phone number
    current_user.phone = new_phone

    db.commit()
    db.refresh(current_user)

    # Remove used OTP
    phone_otp_storage.pop(current_user.id, None)

    return {
        "message": "Phone number changed successfully.",
        "new_phone": current_user.phone
    }
# =========================
# Get Current User
# =========================

@app.get("/me")
def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    return {
        "user_id": current_user.id,
        "full_name": current_user.full_name,
        "username": current_user.username,
        "phone": current_user.phone
    }
