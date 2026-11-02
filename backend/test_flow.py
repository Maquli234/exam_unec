import os, glob
os.environ["ADMIN_EMAIL"] = "admin@test.az"
from fastapi.testclient import TestClient
from app.main import app
c = TestClient(app)
H = lambda t: {"Authorization": "Bearer " + t["access_token"]}
adm = c.post("/auth/register", json={"email": "admin@test.az", "password": "password123", "name": "Admin"}).json()
usr = c.post("/auth/register", json={"email": "u@test.az", "password": "password123", "name": "User"}).json()
pdf = [f for f in glob.glob("/mnt/user-data/uploads/*.pdf") if "00632" in f][0]
r = c.post("/admin/banks", headers=H(usr), files={"file": ("a.pdf", open(pdf, "rb"))}); print("upload user  ->", r.status_code)
r = c.post("/admin/banks", headers=H(adm), files={"file": ("a.pdf", open(pdf, "rb"))}); print("upload admin ->", r.status_code, r.json()["questions"], "вопросов")
bid = r.json()["bank_id"]; print("банки:", c.get("/banks", headers=H(usr)).json())
# immediate-режим, интервал 1-50, 10 вопросов
e = c.post("/exams", headers=H(usr), json={"bank_id": bid, "from_n": 1, "to_n": 50, "count": 10}).json()
nums = [q["file_number"] for q in e["questions"]]
print("номера из файла в разброс:", nums, "| все в 1..50:", all(1 <= n <= 50 for n in nums), "| утечка correct:", any("correct_index" in q for q in e["questions"]))
q0 = e["questions"][0]
a = c.post(f"/exams/{e['exam_id']}/answer", headers=H(usr), json={"question_id": q0["id"], "option_index": 0}).json(); print("immediate ответ:", a)
print("повторный ответ:", c.post(f"/exams/{e['exam_id']}/answer", headers=H(usr), json={"question_id": q0["id"], "option_index": 1}).status_code)
c.post(f"/saved/{q0['id']}", headers=H(usr))
res = c.post(f"/exams/{e['exam_id']}/finish", headers=H(usr)).json(); print("итог:", res["correct"], "из", res["total"], "| ошибки (позиция→№ в файле):", [(w["position"], w["file_number"]) for w in res["wrong"]][:4])
# режим "в конце"
e2 = c.post("/exams", headers=H(usr), json={"bank_id": bid, "count": 3, "answer_mode": "end"}).json()
print("end-режим ответ:", c.post(f"/exams/{e2['exam_id']}/answer", headers=H(usr), json={"question_id": e2["questions"][0]["id"], "option_index": 2}).json())
# сохранённые
e3 = c.post("/exams", headers=H(usr), json={"source": "saved", "count": 99}).json(); print("сохранённые: вопросов", e3["total"])
# токены
r = c.post("/auth/refresh", json={"refresh_token": usr["refresh_token"]}); print("refresh ->", r.status_code)
print("повтор старого refresh ->", c.post("/auth/refresh", json={"refresh_token": usr["refresh_token"]}).status_code, "(ротация работает)")
print("без токена ->", c.get("/banks").status_code)
