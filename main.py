import os
import secrets
import sqlite3
from typing import Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from database import get_db, hash_password, init_db, verify_password

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

init_db()

app = FastAPI(title="CampusConnect")

Category = Literal["Classroom", "Campus", "Lost & Found", "General"]
Status = Literal["Open", "In Progress", "Resolved"]


class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(
        min_length=5, max_length=120, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    )
    password: str = Field(min_length=6, max_length=100)


class LoginIn(BaseModel):
    email: str
    password: str


class IssueIn(BaseModel):
    title: str = Field(min_length=3, max_length=100)
    description: str = Field(min_length=1, max_length=1000)
    category: Category


class StatusIn(BaseModel):
    status: Status


class MessageIn(BaseModel):
    body: str = Field(min_length=1, max_length=1000)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=1000)


def new_session(db: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id)
    )
    return token


def current_user(
    authorization: Optional[str] = Header(None),
    db: sqlite3.Connection = Depends(get_db),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in to continue.")
    token = authorization[7:]
    row = db.execute(
        "SELECT u.id, u.name, u.email, u.role, u.created_at "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token = ?",
        (token,),
    ).fetchone()
    if not row:
        raise HTTPException(401, "Your session has expired. Please log in again.")
    return dict(row)


def require_admin(user: dict = Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Only an admin can do this.")
    return user


@app.post("/api/register", status_code=201)
def register(data: RegisterIn, db: sqlite3.Connection = Depends(get_db)):
    email = data.email.strip().lower()
    try:
        cur = db.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (data.name.strip(), email, hash_password(data.password)),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with this email already exists.")
    return {"token": new_session(db, cur.lastrowid)}


@app.post("/api/login")
def login(data: LoginIn, db: sqlite3.Connection = Depends(get_db)):
    row = db.execute(
        "SELECT id, password_hash FROM users WHERE email = ?",
        (data.email.strip().lower(),),
    ).fetchone()
    if not row or not verify_password(data.password, row["password_hash"]):
        raise HTTPException(401, "Incorrect email or password.")
    return {"token": new_session(db, row["id"])}


@app.post("/api/logout")
def logout(
    authorization: Optional[str] = Header(None),
    db: sqlite3.Connection = Depends(get_db),
):
    if authorization and authorization.startswith("Bearer "):
        db.execute("DELETE FROM sessions WHERE token = ?", (authorization[7:],))
    return {"ok": True}


@app.get("/api/me")
def me(user: dict = Depends(current_user)):
    return user


ISSUE_SELECT = (
    "SELECT i.id, i.title, i.description, i.category, i.status, "
    "i.created_at, i.updated_at, i.created_by, u.name AS author "
    "FROM issues i JOIN users u ON u.id = i.created_by"
)


def get_notes(db: sqlite3.Connection, issue_id: int):
    rows = db.execute(
        "SELECT n.id, n.body, n.created_at, u.name AS author "
        "FROM issue_notes n JOIN users u ON u.id = n.author_id "
        "WHERE n.issue_id = ? ORDER BY n.id DESC",
        (issue_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def load_issue(db: sqlite3.Connection, issue_id: int, user: dict):
    """Fetch an issue the user is allowed to see (own issue, or any if admin)."""
    row = db.execute(ISSUE_SELECT + " WHERE i.id = ?", (issue_id,)).fetchone()
    if not row or (user["role"] != "admin" and row["created_by"] != user["id"]):
        raise HTTPException(404, "This issue doesn't exist or was removed.")
    return dict(row)


@app.get("/api/issues")
def list_issues(
    category: Optional[Category] = None,
    user: dict = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    sql, params = ISSUE_SELECT, []
    clauses = []
    if user["role"] != "admin":
        clauses.append("i.created_by = ?")
        params.append(user["id"])
    if category:
        clauses.append("i.category = ?")
        params.append(category)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    rows = db.execute(sql + " ORDER BY i.id DESC", params).fetchall()
    return [
        {k: v for k, v in dict(r).items() if k != "created_by"} for r in rows
    ]


@app.post("/api/issues", status_code=201)
def create_issue(
    data: IssueIn,
    user: dict = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    cur = db.execute(
        "INSERT INTO issues (title, description, category, created_by) "
        "VALUES (?, ?, ?, ?)",
        (data.title.strip(), data.description.strip(), data.category, user["id"]),
    )
    return {"id": cur.lastrowid}


@app.get("/api/issues/{issue_id}")
def get_issue(
    issue_id: int,
    user: dict = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    issue = load_issue(db, issue_id, user)
    author_id = issue.pop("created_by", None)
    if user["role"] == "admin":
        issue["author_id"] = author_id
    issue["notes"] = get_notes(db, issue_id)
    return issue


@app.patch("/api/issues/{issue_id}/status")
def update_status(
    issue_id: int,
    data: StatusIn,
    user: dict = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db),
):
    cur = db.execute(
        "UPDATE issues SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (data.status, issue_id),
    )
    if cur.rowcount == 0:
        raise HTTPException(404, "This issue doesn't exist or was removed.")
    return {"id": issue_id, "status": data.status}


@app.post("/api/issues/{issue_id}/notes", status_code=201)
def add_note(
    issue_id: int,
    data: NoteIn,
    user: dict = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db),
):
    load_issue(db, issue_id, user)
    cur = db.execute(
        "INSERT INTO issue_notes (issue_id, author_id, body) VALUES (?, ?, ?)",
        (issue_id, user["id"], data.body.strip()),
    )
    db.execute(
        "UPDATE issues SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (issue_id,)
    )
    return {"id": cur.lastrowid}


# ---------------------------------------------------------------- messages
# Each student has one conversation with the admin, identified by student_id.

def thread(db: sqlite3.Connection, student_id: int, reader_id: int):
    """Return a conversation and mark the other side's messages as read."""
    db.execute(
        "UPDATE messages SET read_at = CURRENT_TIMESTAMP "
        "WHERE student_id = ? AND sender_id != ? AND read_at IS NULL",
        (student_id, reader_id),
    )
    rows = db.execute(
        "SELECT m.id, m.body, m.created_at, m.sender_id, u.name AS sender, "
        "u.role AS sender_role FROM messages m JOIN users u ON u.id = m.sender_id "
        "WHERE m.student_id = ? ORDER BY m.id ASC",
        (student_id,),
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/messages/unread")
def unread_count(
    user: dict = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    if user["role"] == "admin":
        n = db.execute(
            "SELECT COUNT(*) FROM messages WHERE read_at IS NULL AND sender_id = student_id"
        ).fetchone()[0]
    else:
        n = db.execute(
            "SELECT COUNT(*) FROM messages WHERE student_id = ? "
            "AND sender_id != ? AND read_at IS NULL",
            (user["id"], user["id"]),
        ).fetchone()[0]
    return {"unread": n}


@app.get("/api/messages")
def my_messages(
    user: dict = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    """A student's own conversation with the admin."""
    if user["role"] == "admin":
        raise HTTPException(400, "Admins use the conversations list.")
    return thread(db, user["id"], user["id"])


@app.post("/api/messages", status_code=201)
def send_message(
    data: MessageIn,
    user: dict = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    if user["role"] == "admin":
        raise HTTPException(400, "Choose a student to message.")
    cur = db.execute(
        "INSERT INTO messages (student_id, sender_id, body) VALUES (?, ?, ?)",
        (user["id"], user["id"], data.body.strip()),
    )
    return {"id": cur.lastrowid}


@app.get("/api/messages/conversations")
def conversations(
    user: dict = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db),
):
    rows = db.execute(
        "SELECT u.id AS student_id, u.name, u.email, "
        "(SELECT body FROM messages WHERE student_id = u.id ORDER BY id DESC LIMIT 1) AS last_body, "
        "(SELECT created_at FROM messages WHERE student_id = u.id ORDER BY id DESC LIMIT 1) AS last_at, "
        "(SELECT COUNT(*) FROM messages WHERE student_id = u.id "
        "   AND sender_id = u.id AND read_at IS NULL) AS unread "
        "FROM users u WHERE u.id IN (SELECT student_id FROM messages) "
        "ORDER BY last_at DESC, u.id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_student(db: sqlite3.Connection, student_id: int):
    row = db.execute(
        "SELECT id, name, email FROM users WHERE id = ? AND role = 'user'",
        (student_id,),
    ).fetchone()
    if not row:
        raise HTTPException(404, "Student not found.")
    return dict(row)


@app.get("/api/messages/conversations/{student_id}")
def student_thread(
    student_id: int,
    user: dict = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db),
):
    student = get_student(db, student_id)
    return {"student": student, "messages": thread(db, student_id, user["id"])}


@app.post("/api/messages/conversations/{student_id}", status_code=201)
def reply_to_student(
    student_id: int,
    data: MessageIn,
    user: dict = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db),
):
    get_student(db, student_id)
    cur = db.execute(
        "INSERT INTO messages (student_id, sender_id, body) VALUES (?, ?, ?)",
        (student_id, user["id"], data.body.strip()),
    )
    return {"id": cur.lastrowid}


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/landing.html")


app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
