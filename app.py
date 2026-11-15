import re
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from google_sheets import _as_date
from flask import Flask

import os
import hmac
from functools import wraps
from flask import jsonify, request, session
from werkzeug.exceptions import HTTPException
from google_sheets import create_sheets_client, GoogleSheetsStore

# ======================= Flask и ошибки =======================

app = Flask(__name__)


class BudgetError(ValueError):
    """Ошибка данных бюджета: текст показывается пользователю."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


# ======================= Веб API и авторизация =======================

app.config.update(
    SECRET_KEY=os.getenv("BUDGET_SECRET_KEY") or os.getenv("GOOGLE_SVC_TOKEN", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30
)

FRONTEND_ORIGIN = "https://oopspoops.github.io"
_budget_store = None


def _json_error(message, status):
    return jsonify({"ok": False, "error": str(message)}), status


def _request_data():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise BudgetError("Некорректный запрос")
    return data


def _get_budget_store():
    global _budget_store
    if _budget_store is None:
        client = create_sheets_client(
            service_email=os.getenv("GOOGLE_SVC_EMAIL", ""),
            private_key=os.getenv("GOOGLE_SVC_TOKEN", "")
        )
        store = GoogleSheetsStore(
            client,
            os.getenv("GOOGLE_SHEET_ID", "")
        )
        _budget_store = BudgetStore(store)
    return _budget_store


def _login_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if not session.get("budget_logged_in"):
            return _json_error("Требуется вход", 401)
        return func(*args, **kwargs)
    return wrapped


def _authorized_users():
    return [
        (os.getenv(f"BUDGET_USER_{i}", ""), os.getenv(f"BUDGET_PASS_{i}", ""))
        for i in (1, 2)
    ]


@app.before_request
def check_origin():
    if request.method == "OPTIONS":
        return "", 204
    origin = request.headers.get("Origin")
    if request.method == "POST" and origin and origin.rstrip("/") != FRONTEND_ORIGIN:
        return _json_error("Запрос запрещён", 403)


@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin")
    if origin and origin.rstrip("/") == FRONTEND_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = FRONTEND_ORIGIN
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Vary"] = "Origin"
    return response


@app.route("/", methods=["GET"])
def home():
    return "Budget App is running!"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})


@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
    data = _request_data()
    username = data.get("username")
    password = data.get("password")

    users = _authorized_users()
    if not all(users):
        return _json_error("Авторизация не настроена", 503)

    valid = False
    if isinstance(username, str) and isinstance(password, str):
        for saved_user, saved_pass in users:
            if (
                hmac.compare_digest(username, saved_user)
                and hmac.compare_digest(password, saved_pass)
            ):
                valid = True

    if not valid:
        return _json_error("Неверный логин или пароль", 401)

    session.clear()
    session["budget_logged_in"] = True
    session.permanent = True
    return jsonify({"ok": True})


@app.route("/api/me", methods=["GET", "OPTIONS"])
def me():
    return jsonify({
        "ok": True,
        "authenticated": bool(session.get("budget_logged_in"))
    })


@app.route("/api/logout", methods=["POST", "OPTIONS"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/budget/periods", methods=["GET", "OPTIONS"])
@_login_required
def budget_periods():
    return jsonify({
        "ok": True,
        "data": build_state(_get_budget_store().read_rows())
    })


@app.route("/api/budget/period/<pay_date>", methods=["GET", "OPTIONS"])
@_login_required
def budget_period(pay_date):
    parsed = parse_iso_date(pay_date)
    state = build_state(_get_budget_store().read_rows())
    return jsonify({"ok": True, "data": find_period(state, parsed)})


@app.route("/api/budget/month/add", methods=["POST", "OPTIONS"])
@_login_required
def budget_month_add():
    expected, salaries = parse_month_request(_request_data())
    result = _get_budget_store().add_month(expected, salaries)
    return jsonify({"ok": True, "data": result})


@app.route("/api/budget/item/add", methods=["POST", "OPTIONS"])
@_login_required
def budget_item_add():
    data = _request_data()
    result = _get_budget_store().add_item(
        parse_iso_date(data.get("pay_date")),
        parse_name(data.get("name")),
        parse_amount(data.get("amount")),
        parse_permanent(data.get("permanent"))
    )
    return jsonify({"ok": True, "data": {"pay_date": result}})


@app.route("/api/budget/item/update", methods=["POST", "OPTIONS"])
@_login_required
def budget_item_update():
    data = _request_data()
    result = _get_budget_store().update_item(
        parse_item_id(data.get("id")),
        parse_name(data.get("name")),
        parse_amount(data.get("amount")),
        parse_permanent(data.get("permanent"))
    )
    return jsonify({"ok": True, "data": {"pay_date": result}})


@app.route("/api/budget/item/delete", methods=["POST", "OPTIONS"])
@_login_required
def budget_item_delete():
    result = _get_budget_store().delete_item(
        parse_item_id(_request_data().get("id"))
    )
    return jsonify({"ok": True, "data": {"pay_date": result}})


@app.route("/api/budget/salary/set", methods=["POST", "OPTIONS"])
@_login_required
def budget_salary_set():
    data = _request_data()
    salary = parse_amount(data["salary"]) if data.get("salary") is not None else None
    extra = parse_amount(data["extra"]) if data.get("extra") is not None else None
    scope = parse_scope(data.get("scope")) if salary is not None else None

    result = _get_budget_store().set_income(
        parse_iso_date(data.get("pay_date")),
        salary,
        scope,
        extra
    )
    return jsonify({"ok": True, "data": {"pay_date": result}})


@app.route("/api/budget/reorder", methods=["POST", "OPTIONS"])
@_login_required
def budget_reorder():
    data = _request_data()
    result = _get_budget_store().reorder(
        parse_iso_date(data.get("pay_date")),
        parse_ids(data.get("ids"))
    )
    return jsonify({"ok": True, "data": {"pay_date": result}})


@app.errorhandler(BudgetError)
def handle_budget_error(error):
    return _json_error(error, error.status)


@app.errorhandler(Exception)
def handle_error(error):
    if isinstance(error, HTTPException):
        return _json_error(error.description, error.code or 500)
    app.logger.exception("Budget API error")
    return _json_error("Внутренняя ошибка сервера", 500)


BUDGET_SHEET = "cost"
BUDGET_HEADER = [
    "id", "pay_date", "salary", "item_name", "permanent", "amount", "delete_flg", "extra_income"
]
BUDGET_COLUMNS = len(BUDGET_HEADER)
LAST_COLUMN = "H"
DATE_FORMAT = {"type": "DATE", "pattern": "dd.MM.yyyy"}
SHEETS_EPOCH = date(1899, 12, 30)
PAY_DAYS = (3, 17)          # две зарплаты в месяц
YES, NO = "Да", "Нет"
NAME_MAX = 60
AMOUNT_MAX = 1_000_000_000
IDS_MAX = 300
MAX_MONTHS_AHEAD = 24       # за один раз можно добавить не больше стольких месяцев вперёд
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

BUDGET_MUTATIONS = frozenset({
    "budget_month_add",
    "budget_item_add",
    "budget_item_update",
    "budget_item_delete",
    "budget_salary_set",
    "budget_reorder",
})
BUDGET_ACTIONS = BUDGET_MUTATIONS | {"budget_periods", "budget_period"}


# ======================= Проверка входных данных =======================
def parse_amount(value, title="Сумма"):
    """Неотрицательное конечное число, не больше AMOUNT_MAX, до копеек."""
    if value is None or isinstance(value, bool):
        raise BudgetError(f"{title}: укажи число")
    if isinstance(value, (int, float)):
        text = repr(value)
    else:
        text = (
            str(value).replace("\u00a0", "").replace(" ", "")
            .replace("₽", "").replace(",", ".")
        )
    if not text.strip():
        raise BudgetError(f"{title}: укажи число")
    try:
        number = Decimal(text)
    except InvalidOperation:
        raise BudgetError(f"{title}: нужно число") from None
    if not number.is_finite():
        raise BudgetError(f"{title}: нужно конечное число")
    if number < 0:
        raise BudgetError(f"{title}: сумма не может быть отрицательной")
    if number > AMOUNT_MAX:
        raise BudgetError(f"{title}: слишком большая сумма")
    number = number.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int(number) if number == number.to_integral_value() else float(number)


def parse_iso_date(value, title="Дата"):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip()):
        raise BudgetError(f"{title}: нужен формат ГГГГ-ММ-ДД")
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        raise BudgetError(f"{title}: такой даты не существует") from None


def parse_month_key(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}", value.strip()):
        raise BudgetError("Месяц: нужен формат ГГГГ-ММ")
    year, month = int(value[:4]), int(value[5:7])
    if not 2000 <= year <= 2100 or not 1 <= month <= 12:
        raise BudgetError("Месяц вне допустимого диапазона")
    return year, month


def parse_name(value):
    if not isinstance(value, str):
        raise BudgetError("Название: нужен текст")
    name = " ".join(value.split())
    if not name:
        raise BudgetError("Название статьи не может быть пустым")
    if len(name) > NAME_MAX:
        raise BudgetError(f"Название: не больше {NAME_MAX} символов")
    return name


def parse_permanent(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"да", "нет"}:
        return value.strip().lower() == "да"
    raise BudgetError("Постоянная: нужно «Да» или «Нет»")


def parse_item_id(value):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BudgetError("Некорректный номер записи")
    return value


def parse_ids(value):
    if not isinstance(value, list) or not value or len(value) > IDS_MAX:
        raise BudgetError("Некорректный порядок статей")
    return [parse_item_id(item) for item in value]


def parse_scope(value):
    if value not in {"one", "future"}:
        raise BudgetError("Не выбран способ применения суммы")
    return value


def parse_request_id(value):
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not REQUEST_ID_RE.match(value):
        raise BudgetError("Некорректный идентификатор запроса")
    return value


def parse_month_request(body):
    """(месяц, зарплаты) для создания месяца.

    month — какой месяц приложение собирается создать (ГГГГ-ММ): сервер сверяет его
    с тем, что получится на самом деле, и этим отсекает повторное нажатие кнопки.
    salary_1 / salary_2 нужны только для самого первого месяца (когда лист пуст).
    """
    expected = parse_month_key(body.get("month")) if body.get("month") else None
    salaries = None
    if body.get("salary_1") is not None or body.get("salary_2") is not None:
        salaries = [
            parse_amount(body.get("salary_1"), "Зарплата (первая)"),
            parse_amount(body.get("salary_2"), "Зарплата (вторая)"),
        ]
    return expected, salaries


# ======================= Даты зарплат =======================
def pay_date_for(year, month, day):
    """Дата выплаты: если выпадает на субботу или воскресенье — предыдущая пятница."""
    result = date(year, month, day)
    if result.weekday() == 5:
        return result - timedelta(days=1)
    if result.weekday() == 6:
        return result - timedelta(days=2)
    return result


def month_pay_dates(year, month):
    return [pay_date_for(year, month, day) for day in PAY_DAYS]


def next_month(year, month):
    return (year + 1, 1) if month == 12 else (year, month + 1)


def month_key(day):
    return f"{day.year:04d}-{day.month:02d}"


# ======================= Разбор листа =======================
def _truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"да", "yes", "y", "true", "1", "+", "x", "✓"}


def _lenient_number(value):
    """Число из ячейки (в таблице могли набрать руками); непонятное — None."""
    if value is None or isinstance(value, bool) or value == "":
        return None
    if isinstance(value, (int, float)):
        number = value
    else:
        text = (
            str(value).replace("\u00a0", "").replace(" ", "")
            .replace("₽", "").replace(",", ".")
        )
        try:
            number = float(text)
        except ValueError:
            return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    return _tidy(number)


def _tidy(number):
    number = round(number, 2)
    return int(number) if number == int(number) else number


def _row_id(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value) if value == int(value) and value > 0 else None
    text = str(value).strip()
    return int(text) if text.isdigit() and int(text) > 0 else None


def parse_rows(values):
    """Все строки листа (в том числе «удалённые»), которые похожи на запись.

    Шапка и мусорные строки (без понятной даты) пропускаются.
    row — номер строки в таблице (с 1), raw — исходные значения A:H.
    """
    rows = []
    for number, raw in enumerate(values, start=1):
        cells = list(raw)[:BUDGET_COLUMNS]
        cells += [""] * (BUDGET_COLUMNS - len(cells))
        if cells[1] == "" or isinstance(cells[1], bool):
            continue
        pay_date = _as_date(cells[1])
        if pay_date is None:
            continue
        amount = _lenient_number(cells[5])
        rows.append({
            "row": number,
            "id": _row_id(cells[0]),
            "date": pay_date,
            "salary": _lenient_number(cells[2]),
            "name": " ".join(str(cells[3]).split()),
            "permanent": _truthy(cells[4]),
            "amount": 0 if amount is None else amount,
            "deleted": _truthy(cells[6]),
            "extra": _lenient_number(cells[7]),
            "raw": cells,
        })
    return rows


def _period_salary(group):
    for row in group:
        if row["salary"] is not None:
            return row["salary"]
    return 0


def _period_extra(group):
    for row in group:
        if row.get("extra") is not None:
            return row["extra"]
    return 0


def build_state(rows):
    """Состояние для приложения: зарплатные периоды по датам со статьями."""
    groups = {}
    for row in rows:
        if not row["deleted"]:
            groups.setdefault(row["date"], []).append(row)

    periods = []
    for day in sorted(groups):
        group = groups[day]
        salary = _period_salary(group)
        extra = _period_extra(group)
        income = _tidy(salary + extra)
        items = [
            {
                "id": row["id"],
                "name": row["name"],
                "permanent": row["permanent"],
                "amount": row["amount"],
            }
            for row in group if row["name"]
        ]
        expenses = _tidy(sum(item["amount"] for item in items))
        periods.append({
            "pay_date": day.isoformat(),
            "month": month_key(day),
            "salary": salary,
            "extra": extra,
            "income": income,
            "expenses": expenses,
            "balance": _tidy(income - expenses),
            "items": items,
        })

    following = None
    if periods:
        last = date.fromisoformat(periods[-1]["pay_date"])
        following = "%04d-%02d" % next_month(last.year, last.month)
    return {"periods": periods, "next_month": following}


def find_period(state, pay_date):
    for period in state["periods"]:
        if period["pay_date"] == pay_date.isoformat():
            return period
    raise BudgetError("Зарплатный период не найден", 404)


# ======================= Создание нового месяца =======================
def _new_row(day, salary, name="", permanent=False, amount=0, extra=0):
    return {
        "date": day, "salary": salary, "name": name,
        "permanent": permanent, "amount": amount, "extra": extra
    }


def _months_between(start, end):
    return (end[0] - start[0]) * 12 + end[1] - start[1]


def _build_chain(groups, start, count):
    """count месяцев подряд, начиная со start. Каждый месяц копирует предыдущий:
    только постоянные статьи (в том числе с суммой 0) и зарплату своего периода.
    groups — [строки первой зарплаты, строки второй] источника."""
    months = []
    year, month = start
    for _ in range(count):
        periods = []
        for day, group in zip(month_pay_dates(year, month), groups):
            salary = _period_salary(group)
            copied = [row for row in group if row["name"] and row["permanent"]]
            periods.append(
                [_new_row(day, salary, row["name"], True, row["amount"]) for row in copied]
                or [_new_row(day, salary)]
            )
        months.append(periods)
        groups = periods
        year, month = next_month(year, month)
    return months


def plan_new_months(rows, expected=None, salaries=None):
    """Строки новых месяцев (без id) и дата первой зарплаты последнего из них.

    Лист не пуст: создаются все месяцы от следующего за последним существующим
    до expected включительно (expected не задан — только следующий), и каждый
    копирует предыдущий. Лист пуст: месяц и две зарплаты задаёт пользователь.
    Строки возвращаются в порядке вставки под шапку: сверху самый новый месяц,
    внутри месяца 17-е выше 3-го. В каждой строке seq — порядок создания (для id).
    """
    active = [row for row in rows if not row["deleted"]]
    if not active:
        if not expected or not salaries:
            raise BudgetError("Укажи месяц и суммы двух зарплат")
        groups = [[_new_row(None, salaries[0])], [_new_row(None, salaries[1])]]
        months = _build_chain(groups, expected, 1)
    else:
        last_day = max(row["date"] for row in active)
        first = next_month(last_day.year, last_day.month)
        target = expected or first
        gap = _months_between(first, target)
        if gap < 0:
            raise BudgetError("Этот месяц уже создан или данные изменились. Обнови страницу.", 409)
        if gap + 1 > MAX_MONTHS_AHEAD:
            raise BudgetError(f"За один раз можно добавить не больше {MAX_MONTHS_AHEAD} месяцев")
        source_dates = sorted({
            row["date"] for row in active
            if (row["date"].year, row["date"].month) == (last_day.year, last_day.month)
        })
        # обычно в последнем месяце две зарплаты; если одна — копируем её в обе
        groups = [
            [row for row in active if row["date"] == source_dates[0]],
            [row for row in active if row["date"] == source_dates[-1]],
        ]
        months = _build_chain(groups, first, gap + 1)

    seq = 0
    for periods in months:                     # id раздаём в хронологическом порядке
        for period_rows in periods:
            for row in period_rows:
                row["seq"] = seq
                seq += 1
    ordered = []
    for periods in reversed(months):           # лист: от новых к старым
        for period_rows in reversed(periods):
            ordered.extend(period_rows)
    return ordered, months[-1][0][0]["date"]


# ======================= Работа с Google Sheets =======================
def _cell(value):
    if value is None or value == "":
        return {}
    if isinstance(value, bool):
        return {"userEnteredValue": {"boolValue": value}}
    if isinstance(value, date):
        return {"userEnteredValue": {"numberValue": (value - SHEETS_EPOCH).days}}
    if isinstance(value, (int, float)):
        return {"userEnteredValue": {"numberValue": value}}
    return {"userEnteredValue": {"stringValue": str(value)}}


def _values_for_sheet(row_id, row):
    return [
        row_id,
        row["date"],
        row["salary"],
        row["name"],
        YES if row["permanent"] else NO,
        row["amount"],
        0,
        row.get("extra", 0),
    ]


def _next_id(rows):
    """Новый номер: больше любого существующего, включая «удалённые» строки."""
    return max((row["id"] for row in rows if row["id"]), default=0) + 1


class BudgetStore:
    """Чтение и запись листа `cost`. Методы синхронные: bot.py вызывает их через
    _call_google_sheets, то есть под общей блокировкой — чтение и запись внутри
    одного метода не перебиваются другим запросом."""

    def __init__(self, store):
        self.store = store
        self._header_ready = False

    # ---------- низкий уровень ----------
    def _values(self):
        return self.store.client.spreadsheets().values()

    def _sheet_id(self, create):
        ids = self.store._get_sheet_ids()
        if BUDGET_SHEET not in ids:
            self.store._sheet_ids = None        # лист могли добавить вручную
            ids = self.store._get_sheet_ids()
        if BUDGET_SHEET in ids:
            return ids[BUDGET_SHEET]
        if not create:
            return None
        return self.store._ensure_sheet(
            BUDGET_SHEET, BUDGET_HEADER, rows=1000, columns=BUDGET_COLUMNS
        )

    def _read_values(self):
        response = self._values().get(
            spreadsheetId=self.store.spreadsheet_id,
            range=f"'{BUDGET_SHEET}'!A:{LAST_COLUMN}",
            valueRenderOption="UNFORMATTED_VALUE"
        ).execute(num_retries=3)
        return response.get("values", [])

    def _write(self, data):
        """Несколько диапазонов одним запросом."""
        if not data:
            return
        self._values().batchUpdate(
            spreadsheetId=self.store.spreadsheet_id,
            body={"valueInputOption": "RAW", "data": data}
        ).execute(num_retries=3)

    def _ensure_header(self, values):
        first = values[0] if values else []
        if len(first) > 1 and first[1] != "" and _as_date(first[1]) is not None:
            return values          # в первой строке уже данные — шапку не трогаем
        if not any(str(cell).strip() for cell in first):
            self._write([{
                "range": f"'{BUDGET_SHEET}'!A1:{LAST_COLUMN}1", "values": [BUDGET_HEADER]
            }])
            return [list(BUDGET_HEADER)] + values[1:]
        self._write([
            {"range": f"'{BUDGET_SHEET}'!{chr(65 + index)}1", "values": [[title]]}
            for index, title in enumerate(BUDGET_HEADER)
            if index >= len(first) or not str(first[index]).strip()
        ])
        return values

    def _repair_ids(self, rows):
        """Строки, добавленные в таблице руками (без id или с повтором), получают новый id."""
        seen, broken = set(), []
        for row in rows:
            if row["id"] is None or row["id"] in seen:
                broken.append(row)
            else:
                seen.add(row["id"])
        if not broken:
            return
        next_id = max(seen, default=0) + 1
        data = []
        for row in broken:
            row["id"] = next_id
            row["raw"][0] = next_id
            data.append({"range": f"'{BUDGET_SHEET}'!A{row['row']}", "values": [[next_id]]})
            next_id += 1
        self._write(data)

    def _repair_dates(self, sheet_id, rows):
        """Даты, записанные текстом (с апострофом), превращаются в настоящие даты."""
        broken = [row for row in rows if isinstance(row["raw"][1], str)]
        if not broken:
            return
        requests = []
        for row in broken:
            requests.append({
                "updateCells": {
                    "start": {"sheetId": sheet_id, "rowIndex": row["row"] - 1, "columnIndex": 1},
                    "rows": [{"values": [{
                        "userEnteredValue": {"numberValue": (row["date"] - SHEETS_EPOCH).days},
                        "userEnteredFormat": {"numberFormat": DATE_FORMAT}
                    }]}],
                    "fields": "userEnteredValue,userEnteredFormat.numberFormat"
                }
            })
        try:
            for index in range(0, len(requests), 200):
                self.store.client.spreadsheets().batchUpdate(
                    spreadsheetId=self.store.spreadsheet_id,
                    body={"requests": requests[index:index + 200]}
                ).execute(num_retries=3)
        except Exception:
            return              # не вышло — прочитать данные это не мешает, исправим в следующий раз
        for row in broken:
            row["raw"][1] = (row["date"] - SHEETS_EPOCH).days

    def _load(self, create=False, write=False):
        sheet_id = self._sheet_id(create)
        if sheet_id is None:
            return None, [], 0
        values = self._read_values()
        if (create or write) and not self._header_ready:
            values = self._ensure_header(values)
            self._header_ready = True
        rows = parse_rows(values)
        self._repair_ids(rows)
        self._repair_dates(sheet_id, rows)
        return sheet_id, rows, len(values)

    def _insert_rows(self, sheet_id, at, row_count, value_rows, inherit_before):
        """Вставляет строки с индексом at (с нуля). Формат берётся у строки выше
        (inherit_before=True) или у той, что окажется под вставкой (False).
        Если под местом вставки данных нет — дописывает в конец. Дата пишется числом,
        её вид задаёт формат ячейки."""
        rows = [{"values": [_cell(value) for value in value_row]} for value_row in value_rows]
        if at >= row_count:
            first_index = row_count
            requests = [{
                "appendCells": {"sheetId": sheet_id, "rows": rows, "fields": "userEnteredValue"}
            }]
        else:
            first_index = at
            requests = [
                {
                    "insertDimension": {
                        "range": {
                            "sheetId": sheet_id,
                            "dimension": "ROWS",
                            "startIndex": at,
                            "endIndex": at + len(value_rows)
                        },
                        "inheritFromBefore": inherit_before
                    }
                },
                {
                    "updateCells": {
                        "start": {"sheetId": sheet_id, "rowIndex": at, "columnIndex": 0},
                        "rows": rows,
                        "fields": "userEnteredValue"
                    }
                }
            ]
        requests.append({
            "updateCells": {
                "start": {"sheetId": sheet_id, "rowIndex": first_index, "columnIndex": 1},
                "rows": [
                    {"values": [{"userEnteredFormat": {"numberFormat": DATE_FORMAT}}]}
                    for _ in value_rows
                ],
                "fields": "userEnteredFormat.numberFormat"
            }
        })
        self.store.client.spreadsheets().batchUpdate(
            spreadsheetId=self.store.spreadsheet_id,
            body={"requests": requests}
        ).execute(num_retries=3)

    def _insert_after(self, sheet_id, after_row, row_count, value_row):
        """Строка сразу под строкой after_row (номер с 1), формат — как у строки выше."""
        self._insert_rows(sheet_id, after_row, row_count, [value_row], True)

    @staticmethod
    def _active_period(rows, pay_date):
        group = [row for row in rows if row["date"] == pay_date and not row["deleted"]]
        if not group:
            raise BudgetError("Зарплатный период не найден", 404)
        return group

    @staticmethod
    def _active_item(rows, item_id):
        for row in rows:
            if row["id"] == item_id and not row["deleted"] and row["name"]:
                return row
        raise BudgetError("Запись не найдена. Обнови страницу.", 404)

    # ---------- чтение ----------
    def read_rows(self):
        return self._load()[1]

    # ---------- изменения ----------
    def add_month(self, expected=None, salaries=None):
        """Новые месяцы вставляются сразу под шапкой — лист идёт от новых к старым.
        Формат строк копируется с бывшей второй строки (она станет ниже)."""
        sheet_id, rows, row_count = self._load(create=True)
        created, focus = plan_new_months(rows, expected, salaries)
        next_id = _next_id(rows)
        value_rows = [_values_for_sheet(next_id + row["seq"], row) for row in created]
        top = 0 if any(row["row"] == 1 for row in rows) else 1     # 1 — под шапкой
        self._insert_rows(sheet_id, top, row_count, value_rows, False)
        return {"focus": focus.isoformat()}

    def add_item(self, pay_date, name, amount, permanent):
        sheet_id, rows, row_count = self._load(write=True)
        group = self._active_period(rows, pay_date)
        salary = _period_salary(group)
        if not any(row["name"] for row in group):
            anchor = group[0]                 # у периода не было статей — занимаем якорь
            self._write([{
                "range": f"'{BUDGET_SHEET}'!D{anchor['row']}:F{anchor['row']}",
                "values": [[name, YES if permanent else NO, amount]]
            }])
            return pay_date.isoformat()
        last_row = max(row["row"] for row in rows if row["date"] == pay_date)
        new_row = _new_row(pay_date, salary, name, permanent, amount, _period_extra(group))
        self._insert_after(sheet_id, last_row, row_count, _values_for_sheet(_next_id(rows), new_row))
        return pay_date.isoformat()

    def update_item(self, item_id, name, amount, permanent):
        _, rows, _ = self._load(write=True)
        row = self._active_item(rows, item_id)
        self._write([{
            "range": f"'{BUDGET_SHEET}'!D{row['row']}:F{row['row']}",
            "values": [[name, YES if permanent else NO, amount]]
        }])
        return row["date"].isoformat()

    def delete_item(self, item_id):
        """Мягкое удаление: delete_flg = 1, строка остаётся в таблице."""
        sheet_id, rows, row_count = self._load(write=True)
        row = self._active_item(rows, item_id)
        others = [
            other for other in rows
            if other["date"] == row["date"] and not other["deleted"] and other["id"] != row["id"]
        ]
        if not others:
            # последняя статья периода: чтобы не потерять период и зарплату,
            # сначала добавляем строку-якорь, потом помечаем статью удалённой
            anchor = _new_row(row["date"], _period_salary([row]), extra=_period_extra([row]))
            self._insert_after(
                sheet_id, row["row"], row_count, _values_for_sheet(_next_id(rows), anchor)
            )
        self._write([{"range": f"'{BUDGET_SHEET}'!G{row['row']}", "values": [[1]]}])
        return row["date"].isoformat()

    def set_income(self, pay_date, salary=None, scope=None, extra=None):
        """Зарплата меняется во всех строках периода; scope «future» — ещё и во всех более
        поздних периодах (по календарной дате, не по номеру строки), прошлое не трогаем.
        Доп. заработок относится только к этому периоду."""
        _, rows, _ = self._load(write=True)
        self._active_period(rows, pay_date)
        data = []
        if salary is not None:
            if scope == "one":
                targets = [row for row in rows if row["date"] == pay_date]
            elif scope == "future":
                targets = [row for row in rows if row["date"] >= pay_date]
            else:
                raise BudgetError("Не выбран способ применения суммы")
            data += [
                {"range": f"'{BUDGET_SHEET}'!C{row['row']}", "values": [[salary]]}
                for row in targets
            ]
        if extra is not None:
            data += [
                {"range": f"'{BUDGET_SHEET}'!{LAST_COLUMN}{row['row']}", "values": [[extra]]}
                for row in rows if row["date"] == pay_date
            ]
        if not data:
            raise BudgetError("Нечего менять")
        self._write(data)
        return pay_date.isoformat()

    def reorder(self, pay_date, ids):
        """Новый порядок статей одного периода. Строки остаются на тех же местах таблицы,
        которые занимали статьи этого периода, — внутри них меняется только очерёдность.
        id, даты и суммы едут вместе со своей строкой и не меняются."""
        _, rows, _ = self._load(write=True)
        items = [
            row for row in rows
            if row["date"] == pay_date and not row["deleted"] and row["name"]
        ]
        by_id = {row["id"]: row for row in items}
        if len(set(ids)) != len(ids) or set(ids) != set(by_id):
            raise BudgetError("Список статей изменился. Обнови страницу и повтори.", 409)
        items.sort(key=lambda row: row["row"])
        if [row["id"] for row in items] == ids:
            return pay_date.isoformat()
        self._write([
            {
                "range": f"'{BUDGET_SHEET}'!A{slot['row']}:{LAST_COLUMN}{slot['row']}",
                "values": [list(by_id[item_id]["raw"])]
            }
            for slot, item_id in zip(items, ids)
        ])
        return pay_date.isoformat()
