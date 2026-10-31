"""The captcha question must be answered to sign in, to create an account, and to start Google sign-in."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from flask.testing import FlaskClient

from conftest import CAPTCHA_QUESTION, attempt, csrf_in, solve_captcha
from secintegrate.storage.db import Database
from secintegrate.web.auth import hash_password
from test_web_auth import EMAIL, PASSWORD, make_client, start_google

WRONG = "999"
MESSAGE = "That answer is not right. Try the new question."


def with_account(tmp_path: Path, db: Database) -> FlaskClient:
    db.set_app_password(EMAIL, hash_password(PASSWORD))
    return make_client(tmp_path, db)


# --- what the pages look like ----------------------------------------------------------------------------------
def test_both_pages_ask_the_question_and_google_is_a_button_not_a_link(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    for path in ("/login", "/signup"):
        page = client.get(path).get_data(as_text=True)
        assert CAPTCHA_QUESTION.search(page) and 'name="captcha"' in page and 'name="website"' in page
        assert 'formaction="/auth/google"' in page and "formnovalidate" in page
        assert 'href="/auth/google"' not in page  # a plain link would skip the question
    assert 'name="from" value="signup"' in client.get("/signup").get_data(as_text=True)


def test_every_page_load_asks_a_new_question(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    client.get("/login")
    with client.session_transaction() as session:
        first = session["captcha"]["nonce"]
    client.get("/login")
    with client.session_transaction() as session:
        assert session["captcha"]["nonce"] != first


# --- the Sign in button ------------------------------------------------------------------------------------------
def test_password_sign_in_needs_the_right_answer(tmp_path: Path, db: Database) -> None:
    client = with_account(tmp_path, db)
    blank = attempt(client, EMAIL, PASSWORD, answer="")
    wrong = attempt(client, EMAIL, PASSWORD, answer=WRONG)
    for response in (blank, wrong):
        assert response.status_code == 400 and MESSAGE in response.get_data(as_text=True)
        assert CAPTCHA_QUESTION.search(response.get_data(as_text=True))  # a new question is shown
    assert client.get("/").status_code == 302  # still signed out, even with the right password
    assert attempt(client, EMAIL, PASSWORD).status_code == 302


def test_a_wrong_answer_says_nothing_about_the_password(tmp_path: Path, db: Database) -> None:
    client = with_account(tmp_path, db)
    right_password = attempt(client, EMAIL, PASSWORD, answer=WRONG).get_data(as_text=True)
    wrong_password = attempt(client, EMAIL, "not the password", answer=WRONG).get_data(as_text=True)
    assert MESSAGE in right_password and MESSAGE in wrong_password
    assert "Wrong email or password" not in right_password and "Wrong email or password" not in wrong_password


def test_wrong_answers_count_toward_the_limit(tmp_path: Path, db: Database) -> None:
    client = with_account(tmp_path, db)
    for _ in range(5):
        assert attempt(client, EMAIL, PASSWORD, answer=WRONG).status_code == 400
    assert attempt(client, EMAIL, PASSWORD).status_code == 429  # even the right answer waits ten minutes


def test_the_hidden_trap_field_blocks_password_sign_in(tmp_path: Path, db: Database) -> None:
    client = with_account(tmp_path, db)
    assert attempt(client, EMAIL, PASSWORD, website="http://spam.example").status_code == 400
    assert client.get("/").status_code == 302


# --- the Google button ---------------------------------------------------------------------------------------------
def test_google_starts_with_the_right_answer(tmp_path: Path, db: Database) -> None:
    location = start_google(make_client(tmp_path, db))
    assert urlparse(location).netloc == "accounts.google.com"


def test_google_is_refused_without_the_answer_and_nothing_is_started(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    for answer in ("", WRONG):
        assert start_google(client, answer=answer) == "/login?error=captcha"
    with client.session_transaction() as session:
        assert "oauth" not in session  # no state or verifier was prepared
    assert MESSAGE in client.get("/login?error=captcha").get_data(as_text=True)


def test_google_from_the_signup_page_returns_to_the_signup_page(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    assert start_google(client, answer=WRONG, page_path="/signup", source="signup") == "/signup?error=captcha"
    page = client.get("/signup?error=captcha").get_data(as_text=True)
    assert MESSAGE in page and "Continue with Google" in page
    location = start_google(client, page_path="/signup", source="signup")
    assert urlparse(location).netloc == "accounts.google.com"


def test_one_answer_starts_google_only_once(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    page = client.get("/login").get_data(as_text=True)
    data = {"captcha": solve_captcha(page), "csrf_token": csrf_in(page)}
    assert urlparse(client.post("/auth/google", data=data).headers["Location"]).netloc == "accounts.google.com"
    assert client.post("/auth/google", data=data).headers["Location"] == "/login?error=captcha"  # replay refused


def test_the_hidden_trap_field_blocks_google(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    assert start_google(client, website="http://spam.example") == "/login?error=captcha"


def test_google_cannot_be_started_by_following_a_link_or_without_a_token(tmp_path: Path, db: Database) -> None:
    client = make_client(tmp_path, db)
    assert client.get("/auth/google").headers["Location"] == "/login"
    page = client.get("/login").get_data(as_text=True)
    assert client.post("/auth/google", data={"captcha": solve_captcha(page)}).status_code == 400  # no CSRF token


def test_coming_back_from_google_needs_no_second_question(tmp_path: Path, db: Database) -> None:
    from urllib.parse import parse_qs

    from test_web_auth import Google

    google = Google()
    client = make_client(tmp_path, db, google)
    db.add_app_user(EMAIL)
    state = parse_qs(urlparse(start_google(client)).query)["state"][0]
    response = client.get(f"/auth/callback?state={state}&code=abc")  # Google's redirect carries no form to answer
    assert response.status_code == 302 and response.headers["Location"] == "/"
