"""XBEN 랩에 actor·owner 계정을 직접 만들어 측정 전제조건을 세운다.

Access Control 랩은 거의 전부 로그인 뒤에 있고, 이 벤치마크는 자격증명을 주지 않는다
(핀 a16cb1b의 104개 .env에는 FLAG 하나뿐이다). 자격증명이 없으면 정찰은 로그인 화면만
보고, access_control.object_identifier는 비교할 두 주체가 없어 후보조차 만들지 못한다.

계정은 취약점이 아니라 전제조건이다. 모의해킹에서 테스트 계정을 받는 것과 같다. IDOR
자체는 여전히 LASP가 찾아야 하며, 이 모듈은 아무것도 탐지하지 않는다.

랩별 비밀을 표로 박지 않는다. 가입 폼을 읽어 입력 타입대로 채우고 계정을 만들기 때문에,
랩이 늘어도 그대로 쓰인다. 랩마다 다른 것은 세 가지뿐이고 모두 여기서 흡수한다.

  * 전송 대상: 폼 ``action``이 있으면 그것, 없으면 페이지 JS의 ``url: '...'`` 리터럴
    (XBEN-069는 register.php가 아니라 api/register.php로 보낸다)
  * 필드 집합: username/password/confirm_password(XBEN-090) 또는
    username/email/password(XBEN-069). 이름이 아니라 **타입**으로 채운다.
  * 성공 신호: 302, JSON ``success: true``, 또는 오류 문구 부재

    python3 scripts/xben_accounts.py http://localhost:63354/
"""

from __future__ import annotations

import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser

# 두 주체의 고정 이름. 측정 간 비교가 가능하도록 랩마다 바뀌지 않게 둔다.
ACTOR_USERNAME = "lasp_actor"
OWNER_USERNAME = "lasp_owner"
ACCOUNT_PASSWORD = "LaspProbe123!"

_REGISTER_PATHS = ("register", "register.php", "signup", "signup.php", "users/new")
_LOGIN_PATHS = ("login", "login.php", "signin", "signin.php", "users/sign_in")
# JS가 선언한 전송 대상. XBEN-069의 register.php는 action 없이 이 형태로만 알려준다.
_JS_URL = re.compile(r"""(?:url\s*:\s*|fetch\s*\(\s*)['"]([^'"]{1,120})['"]""")
# 계정이 이미 있다는 응답은 실패가 아니다. 이전 실행이 만들어 둔 것이므로 전제조건은
# 충족돼 있다. 재실행마다 새 이름을 쓰면 랩에 계정이 쌓이고 측정 간 비교도 흐려진다.
_ALREADY_WORDS = ("already", "exists", "taken", "duplicate")
_FAILURE_WORDS = ("invalid", "error", "failed", "incorrect", "denied")


@dataclass(frozen=True, slots=True)
class FormField:
    name: str
    field_type: str
    value: str


@dataclass(frozen=True, slots=True)
class FormShape:
    """가입·로그인 폼 하나의 전송 대상과 입력 좌표."""

    action: str
    fields: tuple[FormField, ...]

    def field_named_like(self, *needles: str) -> str | None:
        for field in self.fields:
            folded = field.name.casefold()
            if any(needle in folded for needle in needles):
                return field.name
        return None

    @property
    def username_field(self) -> str | None:
        return self.field_named_like("user", "login", "name", "email")

    @property
    def password_field(self) -> str | None:
        for field in self.fields:
            if field.field_type == "password":
                return field.name
        return None

    @property
    def csrf_field(self) -> str | None:
        for field in self.fields:
            if field.field_type == "hidden" and any(
                needle in field.name.casefold()
                for needle in ("csrf", "token", "authenticity", "nonce")
            ):
                return field.name
        return None


@dataclass(frozen=True, slots=True)
class Account:
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class Provisioned:
    """측정에 필요한 두 주체와 그들이 로그인하는 좌표."""

    actor: Account
    owner: Account
    login_url: str
    login_shape: FormShape
    # 로그인 후 실제로 도착한 주소. 세션이 섰는지 확인할 좌표로 쓴다.
    actor_landing: str
    owner_landing: str
    # 두 주체가 각각 소유한 객체의 숫자 ID. 분석기가 이 둘을 서로 바꿔 보낸다.
    actor_object: str | None
    owner_object: str | None


class _FormParser(HTMLParser):
    """폼 하나의 action과 입력 좌표만 읽는다. 값은 보존하되 비밀은 다루지 않는다."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[tuple[str | None, list[FormField]]] = []
        self._open: list[FormField] | None = None
        self._action: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = {key.casefold(): (value or "") for key, value in attrs}
        if tag == "form":
            self._flush()
            self._action = mapping.get("action") or None
            self._open = []
            return
        if tag in {"input", "select", "textarea"} and self._open is not None:
            name = mapping.get("name")
            if not name:
                return
            field_type = (mapping.get("type") or "text").casefold()
            if field_type in {"submit", "button", "reset", "image"}:
                # 전송 버튼 이름은 앱이 요구하는 경우가 있어 값까지 보존한다.
                self._open.append(FormField(name, field_type, mapping.get("value") or ""))
                return
            self._open.append(FormField(name, field_type, mapping.get("value") or ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._flush()

    def _flush(self) -> None:
        if self._open is not None:
            self.forms.append((self._action, list(self._open)))
        self._open = None
        self._action = None

    def close(self) -> None:  # noqa: D102
        super().close()
        self._flush()


def _session() -> urllib.request.OpenerDirector:
    """쿠키를 유지하는 opener를 만든다.

    세션 쿠키 없이 리다이렉트를 따라가면 로그인 결과를 관측할 수 없다. 폼 로그인은
    보통 302로 보호 자원을 가리키고, 쿠키가 없으면 그 자원이 다시 로그인 화면을
    돌려주므로 성공과 실패가 같은 모양이 된다. 주체마다 새 opener를 써서 actor와
    owner 세션이 섞이지 않게 한다.
    """

    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )


def _send(
    opener: urllib.request.OpenerDirector,
    url: str,
    payload: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, str, str]:
    data = urllib.parse.urlencode(payload).encode() if payload is not None else None
    headers = {"User-Agent": "lasp-xben-setup"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            # 리다이렉트를 따라간 최종 좌표. 폼 로그인이 보호 자원으로 보내는 경우
            # 이 값이 "로그인되면 읽을 수 있는 주소"가 되어 세션 검증에 쓰인다.
            return response.status, body, response.geturl()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), url
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, "", url


def _get(url: str, timeout: float = 10.0) -> tuple[int, str]:
    status, body, _final = _send(_session(), url, None, timeout)
    return status, body


def _post(url: str, payload: dict[str, str], timeout: float = 10.0) -> tuple[int, str]:
    status, body, _final = _send(_session(), url, payload, timeout)
    return status, body


def discover_form(base_url: str, paths: tuple[str, ...]) -> tuple[str, FormShape] | None:
    """후보 경로를 돌며 비밀번호 입력이 있는 폼을 찾는다.

    반환하는 action은 절대 URL이다. 폼에 action이 없으면 페이지 JS가 선언한 경로를
    쓰고, 그것도 없으면 폼이 놓여 있던 URL 자신으로 되돌린다.
    """

    for path in paths:
        page_url = urllib.parse.urljoin(base_url, path)
        status, body = _get(page_url)
        if status == 0 or status >= 400 or not body:
            continue
        parser = _FormParser()
        parser.feed(body)
        parser.close()
        for action, fields in parser.forms:
            shape = FormShape(action or "", tuple(fields))
            if shape.password_field is None:
                continue
            target = action
            if not target:
                js = _JS_URL.search(body)
                target = js.group(1) if js else path
            return page_url, FormShape(urllib.parse.urljoin(page_url, target), tuple(fields))
    return None


def _payload_for(shape: FormShape, username: str, password: str) -> dict[str, str]:
    """입력 타입대로 채운다. 이름 규칙에 기대지 않는다.

    확인용 비밀번호 필드가 따로 있어도 password 타입이면 같은 값이 들어가므로
    confirm_password를 따로 알 필요가 없다.
    """

    payload: dict[str, str] = {}
    text_used = False
    for field in shape.fields:
        if field.field_type == "password":
            payload[field.name] = password
        elif field.field_type == "email":
            payload[field.name] = f"{username}@test.local"
        elif field.field_type in {"submit", "button"}:
            payload[field.name] = field.value or "Submit"
        elif field.field_type == "hidden":
            payload[field.name] = field.value
        elif field.field_type in {"text", "search", ""}:
            # 첫 텍스트 좌표를 계정 이름으로 본다. 그 뒤 텍스트 필드는 선택 입력으로
            # 보고 비워 둔다 — 필수인데 비면 성공 판정에서 걸러진다.
            payload[field.name] = username if not text_used else field.value
            text_used = True
        else:
            payload[field.name] = field.value
    return payload


def _registered(status: int, body: str) -> bool:
    """계정이 쓸 수 있는 상태인지 판정한다. 새로 만들었거나 이미 있으면 참."""

    if status in {301, 302, 303}:
        return True
    stripped = body.strip()
    lowered = body.casefold()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict) and "success" in parsed:
            if parsed["success"]:
                return True
            # success=false라도 이미 있다는 뜻이면 전제조건은 충족돼 있다.
            return any(word in lowered for word in _ALREADY_WORDS)
    if status != 200:
        return False
    if any(word in lowered for word in _ALREADY_WORDS):
        return True
    if "success" in lowered or "registered" in lowered:
        return True
    return not any(word in lowered for word in _FAILURE_WORDS)


# owner가 소유할 객체에 심는 표식. 교차 주체 비교가 의미를 가지려면 owner의 자원에
# actor의 자원에는 없는 내용이 있어야 한다.
OWNER_OBJECT_MARKER = "lasp-owner-object-4417"
_CREATE_HINTS = ("create", "new", "add", "post", "write", "compose", "upload")


_NUMERIC_PATH = re.compile(r"/([A-Za-z][A-Za-z0-9_-]{0,39})/(\d{1,10})(?![0-9])")


def _object_ids(body: str) -> set[tuple[str, str]]:
    """본문에서 `/<리소스>/<숫자>` 쌍을 모은다."""

    return set(_NUMERIC_PATH.findall(body))


def _seed_object(
    opener: urllib.request.OpenerDirector,
    landing: str,
    label: str,
    verbose: bool = False,
) -> str | None:
    """한 주체의 세션으로 객체 하나를 만들고 그 **숫자 ID**를 돌려준다.

    접근 통제 분석기는 숫자 객체 ID를 요구한다 — 두 주체의 ID를 서로 바꿔 보내
    응답이 갈리는지 보기 때문이다. 계정명은 ID가 아니다.

    계정만 있으면 "접근 통제가 깨졌나"를 물을 대상이 없다. XBEN-090에서 두 계정을
    만들고도 /edit_draft/<id>가 표면에 올라오지 않은 이유가 이것이다 — 아무도 draft를
    만들지 않았으므로 편집 링크가 생길 수 없었다. 계정과 같은 성격의 전제조건이고,
    취약점이 아니라 무대 설치다.
    """

    status, body, _final = _send(opener, landing)
    if status == 0 or not body:
        return None
    before = _object_ids(body)

    # 생성 폼으로 가는 링크를 착지 페이지에서 찾는다. 경로 이름을 추측하지 않는다.
    candidates: list[str] = []
    for href in re.findall(r"""href\s*=\s*['"]([^'"]{1,200})['"]""", body):
        if any(hint in href.casefold() for hint in _CREATE_HINTS):
            candidates.append(urllib.parse.urljoin(landing, href))
    # 착지 페이지 자체에 생성 폼이 있을 수도 있다.
    candidates.append(landing)

    for page_url in dict.fromkeys(candidates):
        status, page_body, _final = _send(opener, page_url)
        if status == 0 or not page_body:
            continue
        parser = _FormParser()
        parser.feed(page_body)
        parser.close()
        for action, fields in parser.forms:
            shape = FormShape(
                urllib.parse.urljoin(page_url, action or page_url), tuple(fields)
            )
            # 로그인·검색 폼을 집지 않는다. 비밀번호 입력이 있으면 인증 폼이고,
            # 채울 텍스트 좌표가 없으면 만들 내용이 없다.
            if shape.password_field is not None:
                continue
            writable = [
                field
                for field in shape.fields
                if field.field_type in {"text", "textarea", "", "search"}
            ]
            if not writable:
                continue
            payload: dict[str, str] = {}
            for field in shape.fields:
                if field.field_type in {"text", "textarea", "", "search"}:
                    payload[field.name] = OWNER_OBJECT_MARKER
                elif field.field_type in {"submit", "button"}:
                    payload[field.name] = field.value or "Submit"
                else:
                    payload[field.name] = field.value
            status, _body, final = _send(opener, shape.action, payload)
            if verbose:
                print(f"  객체 생성 {shape.action}: status={status}")
            if status in {200, 201, 301, 302, 303}:
                # 폼이 받아들인 것처럼 보이면서 아무것도 만들지 않는 경우가 있다.
                # 주체 자신의 자원에 새 숫자 좌표가 생겼는지로 확인한다.
                _s, check, _f = _send(opener, landing)
                created = _object_ids(check) - before
                if created:
                    resource, value = sorted(created)[0]
                    if verbose:
                        print(f"  객체 확인 [{label}]: /{resource}/{value} 생성됨")
                    return value
                if verbose:
                    print(f"  객체 확인 [{label}]: 새 좌표가 없음 — 다음 폼 시도")
    if verbose:
        print("  객체 생성 폼을 찾지 못했다")
    return None


def _logged_in(status: int, body: str) -> bool:
    """로그인이 성립했는지 판정한다.

    실패한 로그인은 보통 같은 폼을 다시 돌려준다. 그래서 오류 문구가 없다는 것만으로는
    부족하고, 응답에 비밀번호 입력이 다시 들어 있으면 로그인 화면으로 되돌아온 것으로
    본다.
    """

    if status in {301, 302, 303}:
        return True
    if status != 200:
        return False
    lowered = body.casefold()
    stripped = body.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict) and "success" in parsed:
            return bool(parsed["success"])
    if any(word in lowered for word in _FAILURE_WORDS):
        return False
    return 'type="password"' not in lowered and "type='password'" not in lowered


def provision(base_url: str, *, verbose: bool = False) -> Provisioned | None:
    """actor·owner 계정을 만들고 로그인 좌표까지 확인해 돌려준다."""

    register = discover_form(base_url, _REGISTER_PATHS)
    if register is None:
        if verbose:
            print("  가입 폼을 찾지 못했다")
        return None
    register_page, register_shape = register
    if verbose:
        print(f"  가입 폼  {register_page}")
        print(f"  전송 대상 {register_shape.action}")
        print(f"  필드     {[(f.name, f.field_type) for f in register_shape.fields]}")

    # 가입은 최선 노력으로 둔다. 응답으로 성공을 판정하려 하면 랩마다 다른 오류 의미를
    # 추측하게 된다 — XBEN-090은 "already taken"을 200으로, XBEN-069는 같은 상황을
    # 500으로 답한다. 둘 다 계정이 이미 있다는 뜻이고 전제조건은 충족돼 있다. 실제 관문은
    # 아래 로그인 실검증이다.
    for username in (ACTOR_USERNAME, OWNER_USERNAME):
        payload = _payload_for(register_shape, username, ACCOUNT_PASSWORD)
        status, _body = _post(register_shape.action, payload)
        if verbose:
            print(f"  가입 시도 {username}: status={status}")

    login = discover_form(base_url, _LOGIN_PATHS)
    if login is None:
        if verbose:
            print("  로그인 폼을 찾지 못했다")
        return None
    _login_page, login_shape = login
    if verbose:
        print(f"  로그인 대상 {login_shape.action}")

    # 가입 응답의 성공 판정은 휴리스틱이다. 실제로 로그인되는지 확인하지 않으면
    # 존재하지 않는 계정으로 측정을 진행하고 그 실패를 탐지 실패로 집계한다.
    username_field = login_shape.username_field
    password_field = login_shape.password_field
    if not username_field or not password_field:
        if verbose:
            print("  로그인 폼의 좌표를 읽지 못했다")
        return None
    landing: dict[str, str] = {}
    sessions: dict[str, urllib.request.OpenerDirector] = {}
    for account in (ACTOR_USERNAME, OWNER_USERNAME):
        payload = _payload_for(login_shape, account, ACCOUNT_PASSWORD)
        payload[username_field] = account
        payload[password_field] = ACCOUNT_PASSWORD
        # 주체마다 새 세션을 쓴다. 같은 쿠키 저장소를 공유하면 뒤에 로그인한 주체가
        # 앞 주체의 세션을 덮어 두 번째 검증이 항상 통과한다.
        opener = _session()
        sessions[account] = opener
        status, body, final_url = _send(opener, login_shape.action, payload)
        landing[account] = final_url
        if not _logged_in(status, body):
            if verbose:
                print(f"  로그인 실검증 {account}: status={status} -> 실패")
            return None
        if verbose:
            print(f"  로그인 실검증 {account}: 성공")

    return Provisioned(
        actor=Account(ACTOR_USERNAME, ACCOUNT_PASSWORD),
        owner=Account(OWNER_USERNAME, ACCOUNT_PASSWORD),
        login_url=login_shape.action,
        login_shape=login_shape,
        actor_landing=landing.get(ACTOR_USERNAME, base_url),
        owner_landing=landing.get(OWNER_USERNAME, base_url),
        actor_object=_seed_object(
            sessions[ACTOR_USERNAME],
            landing.get(ACTOR_USERNAME, base_url),
            "actor",
            verbose=verbose,
        ),
        owner_object=_seed_object(
            sessions[OWNER_USERNAME],
            landing.get(OWNER_USERNAME, base_url),
            "owner",
            verbose=verbose,
        ),
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    result = provision(argv[1], verbose=True)
    if result is None:
        print("\n전제조건 설정 실패 — 이 랩은 자가 가입으로 계정을 만들 수 없다")
        return 1
    print(f"\nactor={result.actor.username} owner={result.owner.username}")
    print(f"login_url={result.login_url}")
    print(f"actor_object={result.actor_object}  owner_object={result.owner_object}")
    print(f"username_field={result.login_shape.username_field}")
    print(f"password_field={result.login_shape.password_field}")
    print(f"csrf_field={result.login_shape.csrf_field}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
