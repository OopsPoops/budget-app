import json
import re
from datetime import date, datetime, timedelta
from urllib.parse import urlparse


class GoogleSheetsError(Exception):
    """Ошибка доступа к Google Таблице."""


class SheetNotFoundError(GoogleSheetsError):
    """В таблице отсутствует ожидаемый лист."""


class NothingToUndoError(GoogleSheetsError):
    """Нечего отменять: в таблице нет подходящей записи."""


def spreadsheet_id_from_url(spreadsheet_url):
    parsed_url = urlparse(spreadsheet_url)
    match = re.match(
        r"^/spreadsheets/d/([A-Za-z0-9_-]+)(?:/|$)",
        parsed_url.path
    )
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != "docs.google.com"
        or not match
    ):
        raise ValueError("Некорректная ссылка на Google Таблицу.")
    return match.group(1)


def create_sheets_client(credentials_json="", service_email="", private_key=""):
    if credentials_json:
        try:
            service_account_info = json.loads(credentials_json)
        except (TypeError, json.JSONDecodeError) as error:
            raise GoogleSheetsError(
                "GOOGLE_SERVICE_ACCOUNT_JSON содержит некорректный JSON."
            ) from error
    elif service_email and private_key:
        private_key = private_key.replace("\\n", "\n")
        if "PRIVATE KEY" not in private_key:
            raise GoogleSheetsError(
                "GOOGLE_SVC_TOKEN должен содержать PEM-ключ private_key, "
                "а не private_key_id."
            )
        service_account_info = {
            "type": "service_account",
            "client_email": service_email,
            "private_key": private_key,
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    else:
        raise GoogleSheetsError(
            "Задайте GOOGLE_SERVICE_ACCOUNT_JSON либо обе переменные "
            "GOOGLE_SVC_EMAIL и GOOGLE_SVC_TOKEN."
        )

    try:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build
    except ImportError as error:
        raise GoogleSheetsError(
            "Не установлен клиент Google Sheets API."
        ) from error

    try:
        credentials = Credentials.from_service_account_info(
            service_account_info,
            scopes=["https://www.googleapis.com/auth/spreadsheets"]
        )
    except Exception as error:
        raise GoogleSheetsError(
            "Не удалось прочитать credentials сервисного аккаунта; "
            "проверьте email и приватный ключ."
        ) from error

    try:
        return build(
            "sheets",
            "v4",
            credentials=credentials,
            cache_discovery=False
        )
    except Exception as error:
        raise GoogleSheetsError(
            "Не удалось создать клиент Google Sheets API."
        ) from error


def _parse_script_number(value):
    match = re.match(
        r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?",
        str(value).strip().replace(",", ".")
    )
    if not match:
        raise GoogleSheetsError("Значение должно быть числом.")
    number = float(match.group(0))
    if number != number or abs(number) == float("inf"):
        raise GoogleSheetsError("Значение должно быть конечным числом.")
    return number


class GoogleSheetsStore:
    """Прямое чтение и запись в Google Sheets API."""

    REQUIRED_SHEETS = {"total", "sugar", "get_ins"}

    def __init__(self, client, spreadsheet_id):
        self.client = client
        self.spreadsheet_id = spreadsheet_id
        self._sheet_ids = None

    def _get_sheet_ids(self):
        if self._sheet_ids is None:
            response = self.client.spreadsheets().get(
                spreadsheetId=self.spreadsheet_id,
                fields="sheets.properties(sheetId,title)"
            ).execute(num_retries=3)
            self._sheet_ids = {
                sheet["properties"]["title"]: sheet["properties"]["sheetId"]
                for sheet in response.get("sheets", [])
                if "properties" in sheet
            }
        return self._sheet_ids

    def _require_sheet(self, sheet_name):
        sheet_id = self._get_sheet_ids().get(sheet_name)
        if sheet_id is None:
            raise SheetNotFoundError(
                f"В таблице не найден лист «{sheet_name}»."
            )
        return sheet_id

    def read_rows(self, sheet_name, max_rows=None):
        self._require_sheet(sheet_name)
        cell_range = f"'{sheet_name}'!A:F"
        if max_rows:
            cell_range = f"'{sheet_name}'!A1:F{max_rows}"
        response = self.client.spreadsheets().values().get(
            spreadsheetId=self.spreadsheet_id,
            range=cell_range
        ).execute(num_retries=3)
        return response.get("values", [])

    def read_rows_batch(self, sheet_names, max_rows):
        """Верхние строки нескольких листов одним запросом к Google (batchGet)."""
        for name in sheet_names:
            self._require_sheet(name)
        response = self.client.spreadsheets().values().batchGet(
            spreadsheetId=self.spreadsheet_id,
            ranges=[f"'{name}'!A1:F{max_rows}" for name in sheet_names]
        ).execute(num_retries=3)
        ranges = response.get("valueRanges", [])
        return [item.get("values", []) for item in ranges]

    def read_rows_covering(self, sheet_names, start_date, first_rows=1500):
        """Верх листов одним запросом; если окно до start_date не уместилось — читает лист целиком."""
        batches = self.read_rows_batch(sheet_names, first_rows)
        result = []
        for name, rows in zip(sheet_names, batches):
            if len(rows) >= first_rows:
                last = _as_date(rows[-1][0]) if rows[-1] else None
                if last is None or last >= start_date:
                    rows = self.read_rows(name)
            result.append(rows)
        return result

    def insert_measurement(
        self,
        date_str,
        time_str,
        value,
        sheet_name="total"
    ):
        sheet_id = self._require_sheet(sheet_name)

        numeric_value = _parse_script_number(value)

        # Дата и время — числовые значения Google Sheets. Их отображение
        # сохраняется благодаря копированию формата из предыдущей строки.
        parsed_date = datetime.strptime(date_str, "%d.%m.%Y").date()
        parsed_time = datetime.strptime(time_str, "%H:%M").time()
        date_serial = (parsed_date - date(1899, 12, 30)).days
        time_serial = (parsed_time.hour * 60 + parsed_time.minute) / (24 * 60)

        existing_rows = self.read_rows(sheet_name, max_rows=3)
        source_row_index = 2 if len(existing_rows) >= 2 else 1
        copy_requests = [
            {
                "copyPaste": {
                    "source": {
                        "sheetId": sheet_id,
                        "startRowIndex": source_row_index,
                        "endRowIndex": source_row_index + 1,
                        "startColumnIndex": 0,
                        "endColumnIndex": 6
                    },
                    "destination": {
                        "sheetId": sheet_id,
                        "startRowIndex": 1,
                        "endRowIndex": 2,
                        "startColumnIndex": 0,
                        "endColumnIndex": 6
                    },
                    "pasteType": "PASTE_FORMAT",
                    "pasteOrientation": "NORMAL"
                }
            },
            {
                "copyPaste": {
                    "source": {
                        "sheetId": sheet_id,
                        "startRowIndex": source_row_index,
                        "endRowIndex": source_row_index + 1,
                        "startColumnIndex": 3,
                        "endColumnIndex": 5
                    },
                    "destination": {
                        "sheetId": sheet_id,
                        "startRowIndex": 1,
                        "endRowIndex": 2,
                        "startColumnIndex": 3,
                        "endColumnIndex": 5
                    },
                    "pasteType": "PASTE_NORMAL",
                    "pasteOrientation": "NORMAL"
                }
            }
        ]
        requests = [
            {
                "insertDimension": {
                    "range": {
                        "sheetId": sheet_id,
                        "dimension": "ROWS",
                        "startIndex": 1,
                        "endIndex": 2
                    },
                    "inheritFromBefore": False
                }
            }
        ] + copy_requests
        # Вставка строки, перенос формул/оформления и запись данных выполняются
        # одним атомарным batchUpdate. При ошибке запроса не остаётся пустой строки.
        requests.append({
            "updateCells": {
                "start": {
                    "sheetId": sheet_id,
                    "rowIndex": 1,
                    "columnIndex": 0
                },
                "rows": [{
                    "values": [
                        {"userEnteredValue": {"numberValue": date_serial}},
                        {"userEnteredValue": {"numberValue": time_serial}},
                        {"userEnteredValue": {"numberValue": numeric_value}}
                    ]
                }],
                "fields": "userEnteredValue"
            }
        })
        self.client.spreadsheets().batchUpdate(
            spreadsheetId=self.spreadsheet_id,
            body={"requests": requests}
        ).execute(num_retries=3)

    def read_food_rows(self):
        """Лист food: блок A:C (приём пищи, блюдо, выбрано заранее)."""
        response = self.client.spreadsheets().values().get(
            spreadsheetId=self.spreadsheet_id,
            range="'food'!A1:C300"
        ).execute(num_retries=3)
        return response.get("values") or []

    def write_food_rows(self, rows):
        """Полностью перезаписывает блок A:C листа food."""
        values = self.client.spreadsheets().values()
        values.clear(
            spreadsheetId=self.spreadsheet_id,
            range="'food'!A1:C300",
            body={}
        ).execute(num_retries=3)
        if rows:
            values.update(
                spreadsheetId=self.spreadsheet_id,
                range="'food'!A1",
                valueInputOption="RAW",
                body={"values": rows}
            ).execute(num_retries=3)

    def _find_insulin_row(self, date_str, time_str, value):
        """Номер строки (с 1) и сама строка инсулина на листе total по дате, времени и дозе.

        Ищем среди самых свежих: пока пользователь вводил еду, сверху могла появиться другая запись.
        """
        try:
            wanted_date = datetime.strptime(date_str, "%d.%m.%Y").date()
            wanted_time = datetime.strptime(time_str, "%H:%M").time()
            wanted_value = float(str(value).replace(",", "."))
        except (TypeError, ValueError) as error:
            raise GoogleSheetsError("Некорректные данные записи.") from error

        self._require_sheet("total")
        rows = self.client.spreadsheets().values().get(
            spreadsheetId=self.spreadsheet_id,
            range="'total'!A1:G20"      # включая столбец G — там записана еда
        ).execute(num_retries=3).get("values", [])
        for index, row in enumerate(rows):
            if index == 0 or len(row) < 3:
                continue
            if _as_date(row[0]) != wanted_date:
                continue
            row_time = None
            for fmt in ("%H:%M", "%H:%M:%S"):
                try:
                    row_time = datetime.strptime(str(row[1]).strip(), fmt).time()
                    break
                except ValueError:
                    continue
            try:
                row_value = float(str(row[2]).strip().replace(",", "."))
            except ValueError:
                continue
            if row_time is None or row_time.replace(second=0) != wanted_time:
                continue
            if row_value != wanted_value:
                continue
            return index + 1, row
        raise GoogleSheetsError("Строка с этим инсулином не найдена.")

    def add_food(self, date_str, time_str, value, food):
        """Записывает еду в столбец G строки инсулина (лист total); прежний текст заменяется."""
        food = " ".join(str(food).split())[:300]
        if not food:
            raise GoogleSheetsError("Пустая запись о еде.")
        row_number, _ = self._find_insulin_row(date_str, time_str, value)
        self.client.spreadsheets().values().update(
            spreadsheetId=self.spreadsheet_id,
            range=f"'total'!G{row_number}",
            valueInputOption="RAW",
            body={"values": [[food]]}
        ).execute(num_retries=3)
        return row_number

    def read_food(self, date_str, time_str, value):
        """Что уже записано в столбце G у этой записи инсулина (пустая строка, если ничего)."""
        _, row = self._find_insulin_row(date_str, time_str, value)
        return " ".join(str(row[6]).split()) if len(row) > 6 else ""

    # ---------------- Лист get_ins («К врачу») ----------------
    GET_INS_TYPES = ("Короткий", "Ночной")

    def read_get_ins(self):
        """Верх листа get_ins; значения без форматирования (даты — числа)."""
        self._require_sheet("get_ins")
        response = self.client.spreadsheets().values().get(
            spreadsheetId=self.spreadsheet_id,
            range="'get_ins'!A1:Q60",
            valueRenderOption="UNFORMATTED_VALUE"
        ).execute(num_retries=3)
        return response.get("values", [])

    def add_get_ins(self, date_str, received, totals, tests, needles, comment=""):
        """Вставляет две строки под шапку: Короткий и Ночной.

        received / totals: {"Короткий": n, "Ночной": n}.
        Столбцы D, E, G копируются со строк-образцов (формулы сдвигаются сами),
        вручную заполняются A, B, C, F, а в строке короткого ещё H (тест-полоски,
        уп.), I (иглы, уп.) и J (комментарий).
        """
        sheet_id = self._require_sheet("get_ins")
        target_date = _as_date(date_str)
        if target_date is None:
            raise GoogleSheetsError("Дата должна быть в формате ДД.ММ.ГГГГ.")
        serial = (target_date - date(1899, 12, 30)).days

        rows = self.read_get_ins()
        samples = {}
        for index, row in enumerate(rows):
            if index == 0 or len(row) < 2:
                continue
            kind = str(row[1]).strip()
            if kind in self.GET_INS_TYPES and kind not in samples:
                samples[kind] = index
        for kind in self.GET_INS_TYPES:
            if kind not in samples:
                raise GoogleSheetsError(
                    f"На листе get_ins нет строки-образца «{kind}»."
                )

        requests = [{
            "insertDimension": {
                "range": {
                    "sheetId": sheet_id,
                    "dimension": "ROWS",
                    "startIndex": 1,
                    "endIndex": 3
                },
                "inheritFromBefore": False
            }
        }]
        for offset, kind in enumerate(self.GET_INS_TYPES):
            # после вставки двух строк образцы сместились на 2 вниз
            source_index = samples[kind] + 2
            requests.append({
                "copyPaste": {
                    "source": {
                        "sheetId": sheet_id,
                        "startRowIndex": source_index,
                        "endRowIndex": source_index + 1,
                        "startColumnIndex": 0,
                        "endColumnIndex": 10
                    },
                    "destination": {
                        "sheetId": sheet_id,
                        "startRowIndex": 1 + offset,
                        "endRowIndex": 2 + offset,
                        "startColumnIndex": 0,
                        "endColumnIndex": 10
                    },
                    "pasteType": "PASTE_NORMAL",
                    "pasteOrientation": "NORMAL"
                }
            })
        self.client.spreadsheets().batchUpdate(
            spreadsheetId=self.spreadsheet_id,
            body={"requests": requests}
        ).execute(num_retries=3)

        data = []
        for offset, kind in enumerate(self.GET_INS_TYPES):
            row_number = 2 + offset
            data.append({
                "range": f"'get_ins'!A{row_number}:C{row_number}",
                "values": [[serial, kind, received[kind]]]
            })
            data.append({
                "range": f"'get_ins'!F{row_number}",
                "values": [[totals[kind]]]
            })
        data.append({
            "range": "'get_ins'!H2:J2",
            "values": [[tests, needles, comment]]
        })
        self.client.spreadsheets().values().batchUpdate(
            spreadsheetId=self.spreadsheet_id,
            body={"valueInputOption": "RAW", "data": data}
        ).execute(num_retries=3)

    def delete_last_get_ins(self):
        """Удаляет две верхние строки get_ins (последнее поступление)."""
        sheet_id = self._require_sheet("get_ins")
        rows = self.read_get_ins()
        top = rows[1:3]
        kinds = {str(row[1]).strip() for row in top if len(row) > 1}
        same_date = (
            len(top) == 2
            and all(row for row in top)
            and _as_date(top[0][0]) == _as_date(top[1][0])
            and _as_date(top[0][0]) is not None
        )
        if len(top) < 2 or kinds != set(self.GET_INS_TYPES) or not same_date:
            raise NothingToUndoError(
                "Две верхние строки get_ins не похожи на пару "
                "«Короткий + Ночной» за одну дату — удалять ничего не буду."
            )
        deleted = {"date": str(top[0][0])}
        self.client.spreadsheets().batchUpdate(
            spreadsheetId=self.spreadsheet_id,
            body={"requests": [{
                "deleteDimension": {
                    "range": {
                        "sheetId": sheet_id,
                        "dimension": "ROWS",
                        "startIndex": 1,
                        "endIndex": 3
                    }
                }
            }]}
        ).execute(num_retries=3)
        return deleted

    # ---------------- Служебные листы, которые бот создаёт сам ----------------
    def _ensure_sheet(self, title, header, rows=400, columns=12):
        """Возвращает id листа; если листа нет — создаёт его с шапкой."""
        sheet_ids = self._get_sheet_ids()
        if title in sheet_ids:
            return sheet_ids[title]
        try:
            response = self.client.spreadsheets().batchUpdate(
                spreadsheetId=self.spreadsheet_id,
                body={"requests": [{
                    "addSheet": {
                        "properties": {
                            "title": title,
                            "gridProperties": {
                                "rowCount": rows,
                                "columnCount": columns,
                                "frozenRowCount": 1
                            }
                        }
                    }
                }]}
            ).execute(num_retries=3)
            sheet_id = response["replies"][0]["addSheet"]["properties"]["sheetId"]
            self.client.spreadsheets().values().update(
                spreadsheetId=self.spreadsheet_id,
                range=f"'{title}'!A1",
                valueInputOption="RAW",
                body={"values": [header]}
            ).execute(num_retries=3)
        except GoogleSheetsError:
            raise
        except Exception as error:
            raise GoogleSheetsError(
                f"Не удалось создать лист «{title}». Добавь его в таблицу вручную."
            ) from error
        sheet_ids[title] = sheet_id
        return sheet_id

    def _first_column(self, title):
        """Столбец A листа целиком (строки без значения — пустые строки)."""
        response = self.client.spreadsheets().values().get(
            spreadsheetId=self.spreadsheet_id,
            range=f"'{title}'!A:A"
        ).execute(num_retries=3)
        return [str(row[0]).strip() if row else "" for row in response.get("values", [])]

    # ---------------- Лист digest (месячные AI-дайджесты) ----------------
    # Каждая выгрузка — новая строка между шапкой и первой строкой (как сахар и инсулин).
    # Старые выгрузки остаются в таблице как история, приложение берёт самую верхнюю
    # (последнюю) строку месяца.
    DIGEST_SHEET = "digest"
    DIGEST_HEADER = ["month", "created_at", "model", "revision", "json"]
    DIGEST_COLUMNS = 12       # A–L: четыре служебных столбца и до восьми кусков JSON
    DIGEST_CHUNK = 45000      # в ячейке Google Sheets помещается не больше 50 000 символов
    DIGEST_ROWS = 400

    def _ensure_digest_sheet(self):
        return self._ensure_sheet(
            self.DIGEST_SHEET, self.DIGEST_HEADER, self.DIGEST_ROWS, self.DIGEST_COLUMNS
        )

    def read_digest(self, month_key):
        """Последняя выгрузка месяца (dict) или None, если её нет. Лист сам не создаёт."""
        if self.DIGEST_SHEET not in self._get_sheet_ids():
            return None
        tries = 0
        for index, value in enumerate(self._first_column(self.DIGEST_SHEET)):
            if index == 0 or value != month_key:
                continue
            tries += 1
            response = self.client.spreadsheets().values().get(
                spreadsheetId=self.spreadsheet_id,
                range=f"'{self.DIGEST_SHEET}'!A{index + 1}:L{index + 1}"
            ).execute(num_retries=3)
            rows = response.get("values") or [[]]
            payload = "".join(str(cell) for cell in rows[0][4:])
            try:
                digest = json.loads(payload)
            except ValueError:
                digest = None
            if isinstance(digest, dict):
                return digest
            if tries >= 5:   # повреждённые строки пропускаем, ищем ниже предыдущую выгрузку
                break
        return None

    def list_digest_months(self):
        """Ключи месяцев, по которым есть выгрузки («ГГГГ-ММ»), от нового к старому."""
        if self.DIGEST_SHEET not in self._get_sheet_ids():
            return []
        months = {
            value for index, value in enumerate(self._first_column(self.DIGEST_SHEET))
            if index > 0 and re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", value)
        }
        return sorted(months, reverse=True)

    def write_digest(self, month_key, created_at, model, revision, payload_json):
        """Добавляет выгрузку дайджеста новой строкой под шапкой; прежние выгрузки не трогает."""
        sheet_id = self._ensure_digest_sheet()
        chunks = [
            payload_json[index:index + self.DIGEST_CHUNK]
            for index in range(0, len(payload_json), self.DIGEST_CHUNK)
        ] or [""]
        if len(chunks) > self.DIGEST_COLUMNS - 4:
            raise GoogleSheetsError("Дайджест слишком большой для одной строки листа.")

        def text(value):
            return {"userEnteredValue": {"stringValue": str(value)}}

        cells = [
            text(month_key), text(created_at), text(model),
            {"userEnteredValue": {"numberValue": int(revision)}}
        ] + [text(chunk) for chunk in chunks]
        self.client.spreadsheets().batchUpdate(
            spreadsheetId=self.spreadsheet_id,
            body={"requests": [
                {
                    "insertDimension": {
                        "range": {
                            "sheetId": sheet_id,
                            "dimension": "ROWS",
                            "startIndex": 1,
                            "endIndex": 2
                        },
                        "inheritFromBefore": False
                    }
                },
                {
                    "updateCells": {
                        "start": {"sheetId": sheet_id, "rowIndex": 1, "columnIndex": 0},
                        "rows": [{"values": cells}],
                        "fields": "userEnteredValue"
                    }
                }
            ]}
        ).execute(num_retries=3)

    def oldest_data_date(self):
        """Самая ранняя дата в листах sugar и total (для списка месяцев дайджеста)."""
        oldest = None
        sheet_ids = self._get_sheet_ids()
        for name in ("sugar", "total"):
            if name not in sheet_ids:
                continue
            for index, value in enumerate(self._first_column(name)):
                day = _as_date(value) if index else None
                if day and (oldest is None or day < oldest):
                    oldest = day
        return oldest

    # ---------------- Лист settings (общие настройки приложения) ----------------
    # state.json на бесплатном Render стирается при деплое, поэтому общие настройки
    # (целевой диапазон сахара, отчёт, дайджест, графики, таймер) живут в таблице.
    SETTINGS_SHEET = "settings"
    SETTINGS_HEADER = ["key", "value", "updated_at"]

    def read_settings(self):
        """{ключ: значение} из листа settings; лист сам не создаёт."""
        if self.SETTINGS_SHEET not in self._get_sheet_ids():
            return {}
        response = self.client.spreadsheets().values().get(
            spreadsheetId=self.spreadsheet_id,
            range=f"'{self.SETTINGS_SHEET}'!A1:C200"
        ).execute(num_retries=3)
        result = {}
        for row in (response.get("values") or [])[1:]:
            key = str(row[0]).strip() if row else ""
            raw = row[1] if len(row) > 1 else ""
            if not key or not raw:
                continue
            try:
                result[key] = json.loads(raw)
            except ValueError:
                continue
        return result

    def write_setting(self, key, value_json, updated_at):
        """Записывает одну настройку: строка ключа обновляется, нового ключа — добавляется."""
        self._ensure_sheet(self.SETTINGS_SHEET, self.SETTINGS_HEADER, 100, 3)
        row = [key, value_json, updated_at]
        existing = next(
            (
                index for index, value in enumerate(self._first_column(self.SETTINGS_SHEET))
                if index > 0 and value == key
            ),
            None
        )
        values = self.client.spreadsheets().values()
        if existing is None:
            values.append(
                spreadsheetId=self.spreadsheet_id,
                range=f"'{self.SETTINGS_SHEET}'!A:C",
                valueInputOption="RAW",
                insertDataOption="INSERT_ROWS",
                body={"values": [row]}
            ).execute(num_retries=3)
        else:
            values.update(
                spreadsheetId=self.spreadsheet_id,
                range=f"'{self.SETTINGS_SHEET}'!A{existing + 1}:C{existing + 1}",
                valueInputOption="RAW",
                body={"values": [row]}
            ).execute(num_retries=3)

    def write_fact(self, fact_value, date_str):
        sheet_id = self._require_sheet("total")
        existing_rows = self.read_rows("total", max_rows=50)
        target_date = _as_date(date_str)
        if target_date is None:
            raise GoogleSheetsError(
                "Дата факта должна быть в формате ДД.ММ.ГГГГ."
            )
        row_number = next(
            (
                index + 1 for index, row in enumerate(existing_rows)
                if index > 0 and row and _as_date(row[0]) == target_date
            ),
            None
        )

        if row_number is None:
            source_row_index = 2 if len(existing_rows) >= 2 else 1
            self.client.spreadsheets().batchUpdate(
                spreadsheetId=self.spreadsheet_id,
                body={"requests": [
                    {
                        "insertDimension": {
                            "range": {
                                "sheetId": sheet_id,
                                "dimension": "ROWS",
                                "startIndex": 1,
                                "endIndex": 2
                            },
                            "inheritFromBefore": False
                        }
                    },
                    {
                        "copyPaste": {
                            "source": {
                                "sheetId": sheet_id,
                                "startRowIndex": source_row_index,
                                "endRowIndex": source_row_index + 1,
                                "startColumnIndex": 0,
                                "endColumnIndex": 6
                            },
                            "destination": {
                                "sheetId": sheet_id,
                                "startRowIndex": 1,
                                "endRowIndex": 2,
                                "startColumnIndex": 0,
                                "endColumnIndex": 6
                            },
                            "pasteType": "PASTE_FORMAT",
                            "pasteOrientation": "NORMAL"
                        }
                    },
                    {
                        "copyPaste": {
                            "source": {
                                "sheetId": sheet_id,
                                "startRowIndex": source_row_index,
                                "endRowIndex": source_row_index + 1,
                                "startColumnIndex": 3,
                                "endColumnIndex": 5
                            },
                            "destination": {
                                "sheetId": sheet_id,
                                "startRowIndex": 1,
                                "endRowIndex": 2,
                                "startColumnIndex": 3,
                                "endColumnIndex": 5
                            },
                            "pasteType": "PASTE_NORMAL",
                            "pasteOrientation": "NORMAL"
                        }
                    }
                ]}
            ).execute(num_retries=3)
            row_number = 2
            self.client.spreadsheets().values().update(
                spreadsheetId=self.spreadsheet_id,
                range="'total'!A2",
                valueInputOption="RAW",
                body={"values": [[date_str]]}
            ).execute(num_retries=3)

        self.client.spreadsheets().values().update(
            spreadsheetId=self.spreadsheet_id,
            range=f"'total'!F{row_number}",
            valueInputOption="RAW",
            body={"values": [[fact_value]]}
        ).execute(num_retries=3)

    def delete_last_measurement(self, sheet_name):
        """Удаляет последнюю (самую верхнюю) запись листа sugar или total."""
        if sheet_name not in {"sugar", "total"}:
            raise GoogleSheetsError("Отмена доступна только для sugar и total.")
        sheet_id = self._require_sheet(sheet_name)
        rows = self.read_rows(sheet_name, max_rows=50)

        # Новые записи вставляются в строку 2, поэтому ищем первую строку
        # со значением в столбце C (строка только с «фактом» — не запись).
        target_index = next(
            (
                index for index, row in enumerate(rows)
                if index > 0
                and len(row) > 2
                and str(row[2]).strip()
                and _as_date(row[0]) is not None
            ),
            None
        )
        if target_index is None:
            raise NothingToUndoError("Нет записей для отмены.")

        row = rows[target_index]
        row_number = target_index + 1
        deleted = {
            "date": str(row[0]).strip(),
            "time": str(row[1]).strip() if len(row) > 1 else "",
            "value": str(row[2]).strip()
        }

        fact_value = (
            str(row[5]).strip()
            if sheet_name == "total" and len(row) > 5
            else ""
        )
        if fact_value:
            # В этой строке лежит ночной факт дня — не теряем его.
            neighbor = rows[target_index + 1] if target_index + 1 < len(rows) else None
            same_day = bool(
                neighbor
                and _as_date(neighbor[0]) == _as_date(row[0])
            )
            if not same_day:
                # Других строк за этот день нет: очищаем только время и
                # значение, дата и факт остаются.
                self.client.spreadsheets().values().clear(
                    spreadsheetId=self.spreadsheet_id,
                    range=f"'total'!B{row_number}:C{row_number}"
                ).execute(num_retries=3)
                return deleted

        self.client.spreadsheets().batchUpdate(
            spreadsheetId=self.spreadsheet_id,
            body={"requests": [{
                "deleteDimension": {
                    "range": {
                        "sheetId": sheet_id,
                        "dimension": "ROWS",
                        "startIndex": target_index,
                        "endIndex": target_index + 1
                    }
                }
            }]}
        ).execute(num_retries=3)

        if fact_value:
            # Соседняя строка того же дня заняла номер удалённой.
            self.client.spreadsheets().values().update(
                spreadsheetId=self.spreadsheet_id,
                range=f"'total'!F{row_number}",
                valueInputOption="RAW",
                body={"values": [[fact_value]]}
            ).execute(num_retries=3)
        return deleted

    def clear_fact(self, date_str):
        """Очищает ночной факт (столбец F листа total) за указанный день."""
        self._require_sheet("total")
        rows = self.read_rows("total", max_rows=50)
        target_date = _as_date(date_str)
        row_number = next(
            (
                index + 1 for index, row in enumerate(rows)
                if index > 0
                and row
                and _as_date(row[0]) == target_date
                and len(row) > 5
                and str(row[5]).strip()
            ),
            None
        )
        if row_number is None:
            raise NothingToUndoError("Сегодня ночного значения нет.")

        old_value = str(rows[row_number - 1][5]).strip()
        self.client.spreadsheets().values().clear(
            spreadsheetId=self.spreadsheet_id,
            range=f"'total'!F{row_number}"
        ).execute(num_retries=3)
        return {"value": old_value}


def _as_date(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime(1899, 12, 30).date() + timedelta(days=value)
        except (OverflowError, TypeError):
            return None
    for date_format in ("%d.%m.%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value).strip(), date_format).date()
        except ValueError:
            continue
    return None


def configured_spreadsheet_id(explicit_id, spreadsheet_url):
    if explicit_id:
        return explicit_id.strip()
    if spreadsheet_url:
        try:
            return spreadsheet_id_from_url(spreadsheet_url.strip())
        except ValueError as error:
            raise GoogleSheetsError(str(error)) from error
    raise GoogleSheetsError(
        "Не задан GOOGLE_SHEETS_SPREADSHEET_ID или ссылка EXCEL_LINK."
    )
