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
# expire_on_commit=False: иначе после commit каждый объект перечитывается из БД отдельным запросом
# (старт экзамена делал по запросу на каждый вопрос: 50 вопросов -> 55 запросов к БД)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
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
from fastapi.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=1000)   # сжатие ответов: экзамен на 50 вопросов и сама страница весят в разы меньше
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
    # один запрос с группировкой вместо выгрузки всех номеров каждого банка отдельным запросом
    stats = {bid: (n, lo, hi) for bid, n, lo, hi in s.query(Question.bank_id, func.count(), func.min(Question.number),
                                                           func.max(Question.number)).group_by(Question.bank_id)}
    out = []
    for b in s.query(Bank).all():
        n, lo, hi = stats.get(b.id, (0, 0, 0))
        out.append({"id": b.id, "name": b.name, "count": n, "min": lo or 0, "max": hi or 0})
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
    n = len(q.options or [])
    order = (e.option_orders or {}).get(str(q.id))
    if not order or sorted(order) != list(range(n)): order = range(n)   # варианты правили в админке после старта — порядок как в файле
    return [q.options[i] for i in order]
def _keys(opts):
    """Индексы верных вариантов в порядке показа. Пусто — в файле верный не отмечен; бывает и несколько верных."""
    return [i for i, o in enumerate(opts) if o.get("correct")]
def _has_key(q): return any(o.get("correct") for o in q.options or [])
def _verdict(opts, given):
    """Проверка одного ответа. correct=None — проверить нельзя: у вопроса нет отмеченного верного варианта."""
    k = _keys(opts)
    return {"correct": (given in k) if k else None, "correct_index": k[0] if k else None, "correct_indices": k}
def _public(q, e, include_correct=False):
    opts = _opts(q, e)
    d = {"id": q.id, "file_number": q.number, "text": q.text, "options": [o["text"] for o in opts]}
    if include_correct:
        k = _keys(opts); d["correct_index"] = k[0] if k else None; d["correct_indices"] = k
    return d

@app.post("/exams")
def start_exam(b: ExamIn, u: User = Depends(current_user), s: Session = Depends(db)):
    if b.source == "saved":
        if b.bank_id is None: raise HTTPException(400, "bank_id required for saved")   # сохранённые всегда в рамках предмета
        pool = (s.query(Question.id).join(Saved, Saved.question_id == Question.id)
                 .filter(Saved.user_id == u.id, Question.bank_id == b.bank_id))
    else:
        pool = s.query(Question.id).filter_by(bank_id=b.bank_id)
        if b.from_n is not None: pool = pool.filter(Question.number >= b.from_n)
        if b.to_n is not None: pool = pool.filter(Question.number <= b.to_n)
    ids = [i for (i,) in pool]                         # только id: тексты всего банка тянуть из БД не нужно
    if not ids: raise HTTPException(404, "no questions in range")
    count = max(1, min(b.count, len(ids)))
    random.shuffle(ids)                                # порядок вопросов вразброс
    # вопросы без отмеченного верного ответа в экзамен не берём (их нельзя проверить) и добираем следующими из пула.
    # Обычно хватает одного запроса; добор идёт пачками по 500, а не по одному вопросу на запрос
    qs, i, step = [], 0, count
    while len(qs) < count and i < len(ids):
        batch = ids[i:i + step]; i += len(batch); step = 500
        qs += [q for q in _qs(s, batch) if _has_key(q)]
    qs = qs[:count]
    if not qs: raise HTTPException(404, "no questions with a marked answer in range")
    e = Exam(id=uuid.uuid4().hex, user_id=u.id, mode=b.source, answer_mode=b.answer_mode,
             duration_sec=max(1, min(b.duration_min, 300)) * 60, started=int(time.time()), question_ids=[q.id for q in qs],
             answers={}, option_orders=_make_orders(qs) if b.shuffle_options else {})   # порядок вариантов фиксируется на весь экзамен
    s.add(e); s.commit()
    return {"exam_id": e.id, "total": len(qs), "duration_sec": e.duration_sec, "answer_mode": e.answer_mode,
            "questions": [_public(q, e) for q in qs]}   # правильные ответы НЕ отдаются

def _own(s, eid, u):
    e = s.get(Exam, eid)
    if not e or e.user_id != u.id: raise HTTPException(404)
    return e
def _expired(e): return time.time() > e.started + e.duration_sec

@app.get("/exams/{eid}")
def get_exam(eid: str, u: User = Depends(current_user), s: Session = Depends(db)):
    """Начатый экзамен целиком — чтобы продолжить его после перезагрузки страницы (iOS Safari сам перезагружает вкладки из фона).
    Проверка уже данных ответов отдаётся только в режиме «сразу»: там её и так показали при ответе."""
    e = _own(s, eid, u)
    qs = _qs(s, e.question_ids)
    left = {str(q.id) for q in qs}
    answers = {k: v for k, v in (e.answers or {}).items() if k in left}
    results = {}
    if e.answer_mode == "immediate":
        for q in qs:
            if str(q.id) in answers: results[str(q.id)] = _verdict(_opts(q, e), answers[str(q.id)])
    return {"exam_id": e.id, "total": len(qs), "duration_sec": e.duration_sec, "answer_mode": e.answer_mode,
            "remaining_sec": max(0, int(e.started + e.duration_sec - time.time())),
            "overdue_sec": max(0, int(time.time() - e.started - e.duration_sec)), "finished": bool(e.finished),
            "questions": [_public(q, e) for q in qs], "answers": answers, "results": results}

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
    if e.answer_mode == "immediate" and key in e.answers:
        # ответ уже принят (например, ответ сервера потерялся в сети) — не ошибка: отдаём сохранённый ответ и его проверку
        return {**_verdict(opts, e.answers[key]), "given_index": e.answers[key], "already": True}
    e.answers = {**e.answers, key: b.option_index}; s.commit()
    if e.answer_mode == "immediate": return _verdict(opts, b.option_index)
    return {"recorded": True}

@app.post("/exams/{eid}/finish")
def finish(eid: str, u: User = Depends(current_user), s: Session = Depends(db)):
    """Итог экзамена. Повторный вызов безопасен (вернёт тот же итог) — им пользуется повтор после обрыва связи и перезагрузка."""
    e = _own(s, eid, u); e.finished = True; s.commit()
    items, wrong = [], []
    for pos, q in enumerate(_qs(s, e.question_ids), 1):
        k = _keys(_opts(q, e)); given = e.answers.get(str(q.id))
        # nokey: верный вариант не отмечен (вопрос исправили в админке уже после старта) — в счёт не идёт, а не роняет итог
        status = "nokey" if not k else "unanswered" if given is None else "correct" if given in k else "wrong"
        if status in ("wrong", "unanswered"): wrong.append({"position": pos, "file_number": q.number, "status": status})
        items.append({**_public(q, e, True), "position": pos, "given_index": given, "status": status})
    correct = sum(i["status"] == "correct" for i in items)
    return {"correct": correct, "total": sum(i["status"] != "nokey" for i in items), "wrong": wrong, "items": items}


@app.get("/config")
def config(): return {"google_client_id": GOOGLE_CLIENT_ID}
@app.get("/healthz")
def healthz(): return {"ok": True}   # не трогает БД: для пингера, чтобы сайт не засыпал

@app.get("/me")
def me(u: User = Depends(current_user)):
    return {"name": u.name, "email": u.email, "is_admin": u.is_admin}

from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "static"), html=True), name="static")
