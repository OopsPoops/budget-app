import json
from datetime import datetime, timedelta


class GoogleSheetsError(Exception):
    """Ошибка доступа к Google Таблице."""


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


class GoogleSheetsStore:
    """Минимальный доступ к Google Sheets API для приложения бюджета:
    клиент, id таблицы, список листов и создание недостающего листа.
    Всё остальное (чтение и запись листа `cost`) делает BudgetStore в app.py."""

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


def _as_date(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime(1899, 12, 30).date() + timedelta(days=value)
        except (OverflowError, TypeError, ValueError):
            return None
    for date_format in ("%d.%m.%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value).strip(), date_format).date()
        except ValueError:
            continue
    return None
