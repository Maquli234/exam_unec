import os, re, json, time, uuid, random, hashlib, hmac, tempfile
from datetime import datetime, timedelta, timezone
import jwt
from cachetools import TTLCache
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, inspect, text, select, func, Column, Integer, BigInteger, String, Boolean, JSON, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from .parser import parse_pdf, parse_text, to_dicts

SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
ACCESS_MIN, REFRESH_DAYS = 15, 7   # сессия живёт ровно 7 дней с момента входа
DB_URL = os.getenv("DATABASE_URL", "sqlite:///exam.db")
if DB_URL.startswith("postgres://"): DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DB_URL.startswith("postgresql://"): DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
engine = create_engine(DB_URL, pool_pre_ping=True, pool_recycle=240,
                       connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
cache = TTLCache(maxsize=256, ttl=300)  # кеш банков вопросов (в проде заменить на Redis)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True); email = Column(String, unique=True, index=True)
    name = Column(String); pw_hash = Column(String, nullable=True); google_sub = Column(String, nullable=True)
    is_admin = Column(Boolean, default=False)
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    jti = Column(String, primary_key=True); user_id = Column(Integer, ForeignKey("users.id"))
    expires = Column(DateTime); revoked = Column(Boolean, default=False)
class Bank(Base):
    __tablename__ = "banks"
    id = Column(Integer, primary_key=True); name = Column(String); created = Column(DateTime, default=datetime.utcnow)
class Question(Base):
    __tablename__ = "questions"
    id = Column(Integer, primary_key=True); bank_id = Column(Integer, ForeignKey("banks.id"), index=True)
    number = Column(Integer); text = Column(Text); options = Column(JSON)  # [{"text","correct"}]
    needs_review = Column(Boolean, default=False); notes = Column(JSON, default=list)
class Saved(Base):
    __tablename__ = "saved"
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    question_id = Column(Integer, ForeignKey("questions.id"), primary_key=True)
class Exam(Base):
    __tablename__ = "exams"
    id = Column(String, primary_key=True); user_id = Column(Integer, ForeignKey("users.id"))
    mode = Column(String); answer_mode = Column(String); duration_sec = Column(Integer)
    started = Column(BigInteger); question_ids = Column(JSON); answers = Column(JSON, default=dict)
    finished = Column(Boolean, default=False)
    option_orders = Column(JSON, nullable=True)  # {question_id: [исходные индексы в порядке показа]}; пусто = как в файле
Base.metadata.create_all(engine)

def _migrate():
    # create_all не добавляет колонки в уже существующие таблицы -> докидываем вручную (на проде БД уже есть)
    if "option_orders" not in {c["name"] for c in inspect(engine).get_columns("exams")}:
        with engine.begin() as conn: conn.execute(text("ALTER TABLE exams ADD COLUMN option_orders JSON"))
_migrate()

app = FastAPI(title="Exam App")
def db():
    s = SessionLocal()
    try: yield s
    finally: s.close()

# ---------- auth ----------
def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16).hex()
    return salt + "$" + hashlib.scrypt(pw.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
def check_pw(pw, stored):
    salt, _ = stored.split("$"); return hmac.compare_digest(hash_pw(pw, salt), stored)
def tokens(user, s: Session, exp=None):
    now = datetime.now(timezone.utc); jti = uuid.uuid4().hex
    exp = exp or now + timedelta(days=REFRESH_DAYS)  # при обновлении срок сессии НЕ продлевается
    access = jwt.encode({"sub": str(user.id), "type": "access", "exp": now + timedelta(minutes=ACCESS_MIN)}, SECRET, "HS256")
    refresh = jwt.encode({"sub": str(user.id), "type": "refresh", "jti": jti, "exp": exp}, SECRET, "HS256")
    s.add(RefreshToken(jti=jti, user_id=user.id, expires=exp)); s.commit()
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}
def current_user(authorization: str = Header(""), s: Session = Depends(db)):
    try:
        p = jwt.decode(authorization.removeprefix("Bearer "), SECRET, ["HS256"]); assert p["type"] == "access"
    except Exception: raise HTTPException(401, "invalid or expired access token")
    return s.get(User, int(p["sub"]))
def admin_user(u: User = Depends(current_user)):
    if not u.is_admin: raise HTTPException(403, "admin only")
    return u

class RegisterIn(BaseModel): email: EmailStr; password: str; name: str
class LoginIn(BaseModel): email: EmailStr; password: str
class RefreshIn(BaseModel): refresh_token: str
class GoogleIn(BaseModel): id_token: str

@app.post("/auth/register")
def register(b: RegisterIn, s: Session = Depends(db)):
    if len(b.password) < 8: raise HTTPException(400, "password too short")
    if s.query(User).filter_by(email=b.email.lower()).first(): raise HTTPException(409, "email taken")
    u = User(email=b.email.lower(), name=b.name, pw_hash=hash_pw(b.password), is_admin=b.email.lower() == ADMIN_EMAIL.lower())
    s.add(u); s.commit(); return tokens(u, s)
@app.post("/auth/login")
def login(b: LoginIn, s: Session = Depends(db)):
    u = s.query(User).filter_by(email=b.email.lower()).first()
    if not u or not u.pw_hash or not check_pw(b.password, u.pw_hash): raise HTTPException(401, "bad credentials")
    return tokens(u, s)
@app.post("/auth/google")
def google(b: GoogleIn, s: Session = Depends(db)):
    from google.oauth2 import id_token as gid; from google.auth.transport import requests as grq
    try: info = gid.verify_oauth2_token(b.id_token, grq.Request(), GOOGLE_CLIENT_ID)
    except Exception: raise HTTPException(401, "invalid google token")
    if not info.get("email_verified"): raise HTTPException(401, "google email not verified")
    u = s.query(User).filter_by(email=info["email"].lower()).first()
    if not u:
        u = User(email=info["email"].lower(), name=info.get("name", ""), google_sub=info["sub"], is_admin=info["email"].lower() == ADMIN_EMAIL.lower())
        s.add(u); s.commit()
    return tokens(u, s)
@app.post("/auth/refresh")  # ротация: старый refresh отзывается
def refresh(b: RefreshIn, s: Session = Depends(db)):
    try: p = jwt.decode(b.refresh_token, SECRET, ["HS256"]); assert p["type"] == "refresh"
    except Exception: raise HTTPException(401, "invalid refresh token")
    rt = s.get(RefreshToken, p["jti"])
    if not rt or rt.revoked: raise HTTPException(401, "refresh token revoked")
    rt.revoked = True; s.commit()
    return tokens(s.get(User, int(p["sub"])), s, exp=datetime.fromtimestamp(p["exp"], timezone.utc))
@app.post("/auth/logout")
def logout(b: RefreshIn, s: Session = Depends(db)):
    try:
        rt = s.get(RefreshToken, jwt.decode(b.refresh_token, SECRET, ["HS256"])["jti"])
        if rt: rt.revoked = True; s.commit()
    except Exception: pass
    return {"ok": True}

# ---------- admin: банки вопросов ----------
@app.post("/admin/banks")
async def upload_bank(file: UploadFile = File(...), name: str = "", _: User = Depends(admin_user), s: Session = Depends(db)):
    raw = await file.read()
    if file.filename.lower().endswith(".pdf"):
        with tempfile.NamedTemporaryFile(suffix=".pdf") as t: t.write(raw); t.flush(); qs = parse_pdf(t.name)
    else: qs = parse_text(raw.decode("utf-8-sig"))
    if not qs: raise HTTPException(422, "no questions recognized")
    bank = Bank(name=name or file.filename); s.add(bank); s.flush()
    for q in to_dicts(qs): s.add(Question(bank_id=bank.id, **q))
    s.commit()
    return {"bank_id": bank.id, "questions": len(qs), "needs_review": [q.number for q in qs if q.needs_review]}
@app.get("/admin/banks/{bank_id}/questions")
def preview(bank_id: int, only_review: bool = False, _: User = Depends(admin_user), s: Session = Depends(db)):
    q = s.query(Question).filter_by(bank_id=bank_id)
    if only_review: q = q.filter_by(needs_review=True)
    return [dict(id=x.id, number=x.number, text=x.text, options=x.options, notes=x.notes) for x in q.order_by(Question.number)]
class QuestionPatch(BaseModel): text: str | None = None; options: list | None = None
@app.patch("/admin/questions/{qid}")
def patch_question(qid: int, b: QuestionPatch, _: User = Depends(admin_user), s: Session = Depends(db)):
    q = s.get(Question, qid)
    if b.text is not None: q.text = b.text
    if b.options is not None: q.options = b.options
    q.needs_review = False; s.commit(); cache.clear(); return {"ok": True}
@app.delete("/admin/banks/{bank_id}")
def delete_bank(bank_id: int, _: User = Depends(admin_user), s: Session = Depends(db)):
    if not s.get(Bank, bank_id): raise HTTPException(404, "bank not found")
    in_bank = select(Question.id).where(Question.bank_id == bank_id)
    s.query(Saved).filter(Saved.question_id.in_(in_bank)).delete(synchronize_session=False)  # сначала зависимые строки
    n = s.query(Question).filter_by(bank_id=bank_id).delete(synchronize_session=False)
    s.query(Bank).filter_by(id=bank_id).delete(synchronize_session=False)
    s.commit(); cache.clear()
    return {"ok": True, "deleted_questions": n}
@app.get("/banks")
def banks(_: User = Depends(current_user), s: Session = Depends(db)):
    out = []
    for b in s.query(Bank).all():
        nums = [n for (n,) in s.query(Question.number).filter_by(bank_id=b.id)]
        out.append({"id": b.id, "name": b.name, "count": len(nums), "min": min(nums, default=0), "max": max(nums, default=0)})
    return out

# ---------- saved ----------
@app.post("/saved/{qid}")
def save_q(qid: int, u: User = Depends(current_user), s: Session = Depends(db)):
    if not s.get(Question, qid): raise HTTPException(404, "question not found")
    s.merge(Saved(user_id=u.id, question_id=qid)); s.commit(); return {"saved": True}
@app.delete("/saved/{qid}")
def unsave_q(qid: int, u: User = Depends(current_user), s: Session = Depends(db)):
    s.query(Saved).filter_by(user_id=u.id, question_id=qid).delete(); s.commit(); return {"saved": False}
@app.get("/saved/ids")
def saved_ids(u: User = Depends(current_user), s: Session = Depends(db)):
    return {"ids": [r.question_id for r in s.query(Saved).filter_by(user_id=u.id)]}
@app.get("/saved/counts")
def saved_counts(u: User = Depends(current_user), s: Session = Depends(db)):
    """Сколько сохранённых у пользователя в каждом предмете: {bank_id: count}."""
    rows = (s.query(Question.bank_id, func.count()).join(Saved, Saved.question_id == Question.id)
             .filter(Saved.user_id == u.id).group_by(Question.bank_id).all())
    return {str(bank_id): n for bank_id, n in rows}
@app.delete("/saved")
def clear_saved(bank_id: int, u: User = Depends(current_user), s: Session = Depends(db)):
    """Очистить сохранённые только одного предмета (остальные не трогаем)."""
    in_bank = select(Question.id).where(Question.bank_id == bank_id)
    n = s.query(Saved).filter(Saved.user_id == u.id, Saved.question_id.in_(in_bank)).delete(synchronize_session=False)
    s.commit(); return {"ok": True, "removed": n}

# ---------- экзамен ----------
class ExamIn(BaseModel):
    source: str = "bank"            # bank | saved
    bank_id: int | None = None
    from_n: int | None = None       # интервал по номерам из файла
    to_n: int | None = None
    count: int = 50
    duration_min: int = 60
    answer_mode: str = "immediate"  # immediate | end
    shuffle_options: bool = False   # перемешать варианты ответов внутри вопроса

def _qs(s, ids):
    m = {q.id: q for q in s.query(Question).filter(Question.id.in_(ids))}
    return [m[i] for i in ids if i in m]          # вопросы удалённого банка тихо пропускаем

# Варианты вида «все перечисленные» / «ничего из вышеперечисленного» зависят от позиции -> такие вопросы не мешаем
KEEP_ORDER = re.compile(r"все (вышеперечисл|перечисл|вышеуказ|ответы)|ничего из|ни один из|оба (варианта|ответа)|верны оба|"
                        r"yuxarıdakıların|hamısı|heç biri|hər ikisi|all of the above|none of the above|both", re.I)
def _make_orders(qs):
    orders = {}
    for q in qs:
        if len(q.options) < 2 or any(KEEP_ORDER.search(o["text"]) for o in q.options): continue
        p = list(range(len(q.options))); random.shuffle(p); orders[str(q.id)] = p
    return orders
def _opts(q, e):
    """Варианты вопроса в том порядке, в котором их видит пользователь этого экзамена."""
    order = (e.option_orders or {}).get(str(q.id)) or range(len(q.options))
    return [q.options[i] for i in order]
def _correct(opts): return next(i for i, o in enumerate(opts) if o["correct"])
def _public(q, e, include_correct=False):
    opts = _opts(q, e)
    d = {"id": q.id, "file_number": q.number, "text": q.text, "options": [o["text"] for o in opts]}
    if include_correct: d["correct_index"] = _correct(opts)
    return d

@app.post("/exams")
def start_exam(b: ExamIn, u: User = Depends(current_user), s: Session = Depends(db)):
    if b.source == "saved":
        if b.bank_id is None: raise HTTPException(400, "bank_id required for saved")   # сохранённые всегда в рамках предмета
        pool = (s.query(Question).join(Saved, Saved.question_id == Question.id)
                 .filter(Saved.user_id == u.id, Question.bank_id == b.bank_id))
    else:
        pool = s.query(Question).filter_by(bank_id=b.bank_id)
        if b.from_n is not None: pool = pool.filter(Question.number >= b.from_n)
        if b.to_n is not None: pool = pool.filter(Question.number <= b.to_n)
    ids = [q.id for q in pool]
    if not ids: raise HTTPException(404, "no questions in range")
    count = max(1, min(b.count, len(ids)))
    random.shuffle(ids); ids = ids[:count]            # порядок вопросов вразброс
    qs = _qs(s, ids)
    e = Exam(id=uuid.uuid4().hex, user_id=u.id, mode=b.source, answer_mode=b.answer_mode,
             duration_sec=max(1, min(b.duration_min, 300)) * 60, started=int(time.time()), question_ids=ids, answers={},
             option_orders=_make_orders(qs) if b.shuffle_options else {})   # порядок вариантов фиксируется на весь экзамен
    s.add(e); s.commit()
    return {"exam_id": e.id, "total": count, "duration_sec": e.duration_sec, "answer_mode": e.answer_mode,
            "questions": [_public(q, e) for q in qs]}   # правильные ответы НЕ отдаются

def _own(s, eid, u):
    e = s.get(Exam, eid)
    if not e or e.user_id != u.id: raise HTTPException(404)
    return e
def _expired(e): return time.time() > e.started + e.duration_sec

class AnswerIn(BaseModel): question_id: int; option_index: int
@app.post("/exams/{eid}/answer")
def answer(eid: str, b: AnswerIn, u: User = Depends(current_user), s: Session = Depends(db)):
    e = _own(s, eid, u)
    if e.finished or _expired(e): raise HTTPException(409, "exam finished")
    if b.question_id not in e.question_ids: raise HTTPException(400, "question not in exam")
    q = s.get(Question, b.question_id)
    if not q: raise HTTPException(404, "question was deleted")
    opts = _opts(q, e)
    if not 0 <= b.option_index < len(opts): raise HTTPException(400, "bad option index")
    key = str(b.question_id)
    if e.answer_mode == "immediate" and key in e.answers: raise HTTPException(409, "already answered")
    e.answers = {**e.answers, key: b.option_index}; s.commit()
    if e.answer_mode == "immediate":
        ci = _correct(opts)
        return {"correct": ci == b.option_index, "correct_index": ci}
    return {"recorded": True}

@app.post("/exams/{eid}/finish")
def finish(eid: str, u: User = Depends(current_user), s: Session = Depends(db)):
    e = _own(s, eid, u); e.finished = True; s.commit()
    items, wrong = [], []
    for pos, q in enumerate(_qs(s, e.question_ids), 1):
        ci = _correct(_opts(q, e)); given = e.answers.get(str(q.id))
        status = "unanswered" if given is None else ("correct" if given == ci else "wrong")
        if status != "correct": wrong.append({"position": pos, "file_number": q.number, "status": status})
        items.append({**_public(q, e, True), "position": pos, "given_index": given, "status": status})
    correct = sum(i["status"] == "correct" for i in items)
    return {"correct": correct, "total": len(items), "wrong": wrong, "items": items}


@app.get("/config")
def config(): return {"google_client_id": GOOGLE_CLIENT_ID}
@app.get("/healthz")
def healthz(): return {"ok": True}   # не трогает БД: для пингера, чтобы сайт не засыпал

@app.get("/me")
def me(u: User = Depends(current_user)):
    return {"name": u.name, "email": u.email, "is_admin": u.is_admin}

from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "static"), html=True), name="static")
