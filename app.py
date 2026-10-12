
from flask import Flask, render_template, request, jsonify, session
import time
import sqlite3
import secrets
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vyslo_chat.db")


def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)

        # 既存ユーザーは承認済みのまま維持する
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(users)").fetchall()
        }
        if "approved" not in columns:
            db.execute("""
                ALTER TABLE users
                ADD COLUMN approved INTEGER NOT NULL DEFAULT 1
            """)

        # 利用停止状態を追加する（既存ユーザーは通常利用のまま）
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(users)").fetchall()
        }
        if "suspended" not in columns:
            db.execute("""
                ALTER TABLE users
                ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0
            """)

        # 新規申請者は承認されるまで待機する
        db.execute("""
            CREATE TABLE IF NOT EXISTS account_requests (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT ''
            )
        """)

        # 以前作成したデータベースにも説明欄を追加する
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(rooms)").fetchall()
        }
        if "description" not in columns:
            db.execute("""
                ALTER TABLE rooms
                ADD COLUMN description TEXT NOT NULL DEFAULT ''
            """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS memberships (
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                PRIMARY KEY (room_id, username)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS join_requests (
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                PRIMARY KEY (room_id, username)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS reactions (
                room_id TEXT NOT NULL,
                message_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                emoji TEXT NOT NULL,
                PRIMARY KEY (message_id, username, emoji)
            )
        """)

        # 部屋で浮かぶ絵文字
        db.execute("""
            CREATE TABLE IF NOT EXISTS floating_emojis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                emoji TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS raised_hands (
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                raised_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (room_id, username)
            )
        """)


        # 部屋ごとのBAN記録
        db.execute("""
            CREATE TABLE IF NOT EXISTS room_bans (
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                banned_by TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (room_id, username)
            )
        """)

        # 既存のBANテーブルにも理由欄を追加
        ban_columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(room_bans)").fetchall()
        }
        if "reason" not in ban_columns:
            db.execute("""
                ALTER TABLE room_bans
                ADD COLUMN reason TEXT NOT NULL DEFAULT ''
            """)

        # room_bans_reason_migration

        # 削除されたメッセージの保管庫
        db.execute("""
            CREATE TABLE IF NOT EXISTS deleted_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_message_id INTEGER NOT NULL,
                room_id TEXT NOT NULL,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                deleted_by TEXT NOT NULL,
                deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)



        # 環境変数から管理者アカウントを作成
        admin_username = os.environ.get("WEB_ADMIN_USERNAME", "").strip()
        admin_password = os.environ.get("WEB_ADMIN_PASSWORD", "")

        if admin_username and admin_password:
            existing_admin = db.execute(
                "SELECT 1 FROM users WHERE username = ?",
                (admin_username,)
            ).fetchone()

            if not existing_admin:
                db.execute(
                    """
                    INSERT INTO users
                    (username, password_hash, approved, suspended)
                    VALUES (?, ?, 1, 0)
                    """,
                    (
                        admin_username,
                        generate_password_hash(admin_password)
                    )
                )

                db.execute(
                    "DELETE FROM account_requests WHERE username = ?",
                    (admin_username,)
                )

init_db()

with connect_db() as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS user_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            is_read INTEGER NOT NULL DEFAULT 0
        )
    """)



def current_user():
    return session.get("username")


def require_login():
    username = current_user()

    if not username:
        return jsonify({"error": "ログインしてね"}), 401

    with connect_db() as db:
        user = db.execute(
            "SELECT approved, suspended FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if not user or not user["approved"]:
        session.clear()
        return jsonify({"error": "このアカウントは利用できないよ"}), 403

    if user["suspended"]:
        session.clear()
        return jsonify({"error": "このアカウントは利用停止中だよ"}), 403

    return None


def is_member(db, room_id, username):
    return db.execute("""
        SELECT 1 FROM memberships
        WHERE room_id = ? AND username = ?
    """, (room_id, username)).fetchone() is not None




def can_access_room(db, room_id, username):
    return is_web_admin(username) or is_member(db, room_id, username)

def is_room_admin(db, room_id, username):
    return db.execute("""
        SELECT 1 FROM memberships
        WHERE room_id = ? AND username = ? AND role = 'admin'
    """, (room_id, username)).fetchone() is not None


def is_web_admin(username):
    admin = os.environ.get("WEB_ADMIN_USERNAME", "").strip()
    return (
        bool(admin)
        and username == admin
        and session.get("web_admin") is True
    )


@app.route("/")
def home():
    if current_user():
        return render_template("chat.html", is_web_admin=is_web_admin(current_user()))
    return render_template("index.html")


@app.route("/chat")
def chat():
    if not current_user():
        return render_template("index.html")
    return render_template("chat.html", is_web_admin=is_web_admin(current_user()))


@app.route("/api/me")
def me():
    username = current_user()
    if not username:
        return jsonify({"logged_in": False}), 401
    return jsonify({"logged_in": True, "username": username})


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not 3 <= len(username) <= 20:
        return jsonify({"error": "ユーザー名は3〜20文字にしてね"}), 400
    if len(password) < 6:
        return jsonify({"error": "パスワードは6文字以上にしてね"}), 400
    if len(password) > 128:
        return jsonify({"error": "パスワードは128文字以内にしてね"}), 400

    with connect_db() as db:
        exists = db.execute(
            "SELECT 1 FROM users WHERE username = ? "
            "UNION SELECT 1 FROM account_requests WHERE username = ?",
            (username, username)
        ).fetchone()

        if exists:
            return jsonify({"error": "そのユーザー名はすでに使われているよ"}), 409

        db.execute("""
            INSERT INTO account_requests (username, password_hash)
            VALUES (?, ?)
        """, (username, generate_password_hash(password)))

    return jsonify({
        "message": "アカウント申請を受け付けたよ！管理者の承認を待ってね。"
    }), 202


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    admin_password = str(data.get("admin_password", ""))

    admin_username = os.environ.get("WEB_ADMIN_USERNAME", "").strip()
    configured_admin_password = os.environ.get("WEB_ADMIN_PASSWORD", "")

    with connect_db() as db:
        user = db.execute("""
            SELECT password_hash, approved, suspended
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "ユーザー名かパスワードが違うよ"}), 403

    if not user["approved"]:
        return jsonify({"error": "管理者の承認がまだ終わっていないよ"}), 403

    if user["suspended"]:
        return jsonify({"error": "このアカウントは利用停止中だよ"}), 403

    # 管理者アカウントでは、専用パスワードも必須
    if admin_username and username == admin_username:
        if not configured_admin_password or not secrets.compare_digest(
            admin_password, configured_admin_password
        ):
            return jsonify({"error": "管理者パスワードが違うよ"}), 403

        session.clear()
        session["username"] = username
        session["web_admin"] = True
        return jsonify({
            "message": "管理者としてログインしたよ！",
            "username": username,
            "is_web_admin": True
        })

    session.clear()
    session["username"] = username
    return jsonify({
        "message": "ログインしたよ！",
        "username": username,
        "is_web_admin": False
    })


@app.route("/admin/accounts")
def admin_accounts_page():
    if not current_user():
        return render_template("index.html")
    if not is_web_admin(current_user()):
        return "管理者だけがアクセスできるよ", 403
    return render_template("admin_accounts.html")



@app.route("/api/admin/users")
def admin_users_api():
    error = require_login()
    if error:
        return error
    if not is_web_admin(current_user()):
        return jsonify({"error": "管理者だけが使えるよ"}), 403

    with connect_db() as db:
        users = db.execute("""
            SELECT username, approved, suspended
            FROM users
            ORDER BY username
        """).fetchall()

    admin_username = os.environ.get("WEB_ADMIN_USERNAME", "").strip()
    result = []
    for row in users:
        item = dict(row)
        item["is_web_admin"] = item["username"] == admin_username
        result.append(item)

    return jsonify(result)


@app.route("/api/admin/users/status", methods=["POST"])
def admin_user_status_api():
    error = require_login()
    if error:
        return error
    if not is_web_admin(current_user()):
        return jsonify({"error": "管理者だけが使えるよ"}), 403

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    action = str(data.get("action", "")).strip()

    if not username or action not in ("suspend", "restore"):
        return jsonify({"error": "指定内容を確認してね"}), 400

    admin_username = os.environ.get("WEB_ADMIN_USERNAME", "").strip()
    if username == admin_username:
        return jsonify({"error": "管理者アカウントは変更できないよ"}), 403

    with connect_db() as db:
        user = db.execute(
            "SELECT username FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if not user:
            return jsonify({"error": "ユーザーが見つからないよ"}), 404

        suspended = 1 if action == "suspend" else 0
        db.execute(
            "UPDATE users SET suspended = ? WHERE username = ?",
            (suspended, username)
        )

    message = "利用停止にしたよ" if suspended else "利用停止を解除したよ"
    return jsonify({"message": username + " さんを" + message})


@app.route("/api/admin/overview")
def admin_overview_api():
    error = require_login()
    if error:
        return error
    if not is_web_admin(current_user()):
        return jsonify({"error": "管理者だけが使えるよ"}), 403

    with connect_db() as db:
        user_count = db.execute(
            "SELECT COUNT(*) FROM users WHERE approved = 1"
        ).fetchone()[0]
        suspended_count = db.execute(
            "SELECT COUNT(*) FROM users WHERE suspended = 1"
        ).fetchone()[0]
        room_count = db.execute(
            "SELECT COUNT(*) FROM rooms"
        ).fetchone()[0]
        message_count = db.execute(
            "SELECT COUNT(*) FROM messages"
        ).fetchone()[0]

    return jsonify({
        "user_count": user_count,
        "suspended_count": suspended_count,
        "room_count": room_count,
        "message_count": message_count
    })


@app.route("/api/admin/rooms")
def admin_rooms_api():
    error = require_login()
    if error:
        return error
    if not is_web_admin(current_user()):
        return jsonify({"error": "管理者だけが使えるよ"}), 403

    with connect_db() as db:
        rooms = db.execute("""
            SELECT
                r.id,
                r.name,
                r.created_by,
                (SELECT COUNT(*) FROM memberships m
                 WHERE m.room_id = r.id) AS participant_count,
                (SELECT COUNT(*) FROM messages msg
                 WHERE msg.room_id = r.id) AS message_count
            FROM rooms r
            ORDER BY r.name
        """).fetchall()

    return jsonify([dict(row) for row in rooms])

@app.route("/api/admin/account-requests", methods=["GET"])
def admin_account_requests():
    error = require_login()
    if error:
        return error

    if not is_web_admin(current_user()):
        return jsonify({"error": "管理者だけが使える機能だよ"}), 403

    with connect_db() as db:
        rows = db.execute("""
            SELECT username, created_at
            FROM account_requests
            ORDER BY created_at ASC
        """).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route("/api/admin/account-requests/respond", methods=["POST"])
def respond_account_request():
    error = require_login()
    if error:
        return error

    if not is_web_admin(current_user()):
        return jsonify({"error": "管理者だけが使える機能だよ"}), 403

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    action = data.get("action")

    if action not in ("approve", "reject") or not username:
        return jsonify({"error": "申請者と操作を確認してね"}), 400

    with connect_db() as db:
        applicant = db.execute("""
            SELECT username, password_hash
            FROM account_requests
            WHERE username = ?
        """, (username,)).fetchone()

        if not applicant:
            return jsonify({"error": "申請が見つからないよ"}), 404

        if action == "approve":
            db.execute("""
                INSERT INTO users (username, password_hash, approved)
                VALUES (?, ?, 1)
            """, (applicant["username"], applicant["password_hash"]))

        db.execute(
            "DELETE FROM account_requests WHERE username = ?",
            (username,)
        )

    message = "アカウントを承認したよ" if action == "approve" else "申請を却下したよ"
    return jsonify({"message": message})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "ログアウトしたよ"})


@app.route("/api/rooms")
def list_rooms():
    error = require_login()
    if error:
        return error

    username = current_user()

    with connect_db() as db:
        rooms = db.execute("""
            SELECT
                r.id, r.name, r.description, m.role,
                'joined' AS status
            FROM rooms r
            JOIN memberships m ON r.id = m.room_id
            WHERE m.username = ?

            UNION ALL

            SELECT
                r.id, r.name, r.description, '' AS role,
                'pending' AS status
            FROM rooms r
            JOIN join_requests jr ON r.id = jr.room_id
            WHERE jr.username = ?
              AND jr.status = 'pending'
              AND NOT EXISTS (
                  SELECT 1 FROM memberships m
                  WHERE m.room_id = r.id
                    AND m.username = ?
              )
            ORDER BY name
        """, (username, username, username)).fetchall()

    return jsonify({"rooms": [dict(room) for room in rooms]})

@app.route("/api/create-room", methods=["POST"])
def create_room():
    error = require_login()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()

    if not name:
        return jsonify({"error": "ルーム名を入力してね"}), 400
    if len(name) > 40:
        return jsonify({"error": "ルーム名は40文字以内だよ"}), 400
    if len(description) > 500:
        return jsonify({"error": "説明は500文字以内だよ"}), 400

    username = current_user()
    room_id = secrets.token_hex(4)

    with connect_db() as db:
        db.execute("""
            INSERT INTO rooms (id, name, password_hash, created_by, description)
            VALUES (?, ?, '', ?, ?)
        """, (room_id, name, username, description))

        db.execute("""
            INSERT INTO memberships (room_id, username, role)
            VALUES (?, ?, 'admin')
        """, (room_id, username))

    return jsonify({
        "message": "ルームを作成したよ！",
        "room_id": room_id
    })


@app.route("/api/join-room", methods=["POST"])
def join_room():
    error = require_login()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    room_id = str(data.get("room_id", "")).strip()
    username = current_user()

    if not room_id:
        return jsonify({"error": "ルームIDを入力してね"}), 400

    with connect_db() as db:
        room = db.execute(
            "SELECT id FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()

        if not room:
            return jsonify({"error": "ルームが見つからないよ"}), 404

        banned = db.execute("""
            SELECT 1 FROM room_bans
            WHERE room_id = ? AND username = ?
        """, (room_id, username)).fetchone()

        if banned:
            return jsonify({"error": "このルームへの参加は禁止されているよ"}), 403

        if is_member(db, room_id, username):
            return jsonify({"error": "すでに参加しているよ"}), 409

        db.execute("""
            INSERT INTO join_requests (room_id, username, status)
            VALUES (?, ?, 'pending')
            ON CONFLICT(room_id, username)
            DO UPDATE SET status = 'pending'
        """, (room_id, username))

    return jsonify({"message": "参加申請を送ったよ！管理者の承認を待ってね"})


@app.route("/api/join-requests")
def list_join_requests():
    error = require_login()
    if error:
        return error

    with connect_db() as db:
        rows = db.execute("""
            SELECT jr.room_id, r.name AS room_name,
                   jr.username AS applicant
            FROM join_requests jr
            JOIN rooms r ON r.id = jr.room_id
            JOIN memberships m ON m.room_id = r.id
            WHERE m.username = ?
              AND m.role = 'admin'
              AND jr.status = 'pending'
            ORDER BY jr.rowid
        """, (current_user(),)).fetchall()

    return jsonify({"requests": [dict(row) for row in rows]})


@app.route("/api/respond-join-request", methods=["POST"])
def respond_join_request():
    error = require_login()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    room_id = str(data.get("room_id", "")).strip()
    applicant = str(data.get("applicant", "")).strip()
    action = str(data.get("action", "")).strip()

    if not room_id or not applicant or action not in ("approve", "reject"):
        return jsonify({"error": "申請内容を確認してね"}), 400

    with connect_db() as db:
        if not is_room_admin(db, room_id, current_user()):
            return jsonify({"error": "ルーム管理者だけが操作できるよ"}), 403

        pending = db.execute("""
            SELECT 1 FROM join_requests
            WHERE room_id = ? AND username = ? AND status = 'pending'
        """, (room_id, applicant)).fetchone()

        if not pending:
            return jsonify({"error": "申請が見つからないよ"}), 404

        if action == "approve":
            banned = db.execute("""
                SELECT 1 FROM room_bans
                WHERE room_id = ? AND username = ?
            """, (room_id, applicant)).fetchone()

            if banned:
                return jsonify({"error": "このユーザーはBANされているよ"}), 403

            db.execute("""
                INSERT OR IGNORE INTO memberships (room_id, username, role)
                VALUES (?, ?, 'member')
            """, (room_id, applicant))
            status = "approved"
        else:
            status = "rejected"

        db.execute("""
            UPDATE join_requests SET status = ?
            WHERE room_id = ? AND username = ?
        """, (status, room_id, applicant))

    return jsonify({"message": "承認したよ！" if action == "approve" else "拒否したよ"})


@app.route("/api/leave-room", methods=["POST"])
def leave_room():
    error = require_login()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    room_id = str(data.get("room_id", "")).strip()
    username = current_user()

    if not room_id:
        return jsonify({"error": "部屋IDを確認してね"}), 400

    with connect_db() as db:
        room = db.execute(
            "SELECT id, name FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()

        if not room:
            return jsonify({"error": "部屋が見つからないよ"}), 404

        if not is_member(db, room_id, username):
            return jsonify({"error": "この部屋の参加者ではないよ"}), 403

        if is_room_admin(db, room_id, username):
            admins = db.execute("""
                SELECT COUNT(*) AS total FROM memberships
                WHERE room_id = ? AND role = 'admin'
            """, (room_id,)).fetchone()["total"]

            if admins <= 1:
                return jsonify({
                    "error": "最後の管理者は脱退できないよ。先に別の参加者へ管理者を引き継いでね"
                }), 409

        # 部屋に残る人へ見える脱退通知を保存する
        db.execute("""
            INSERT INTO messages (room_id, username, content)
            VALUES (?, 'システム', ?)
        """, (room_id, f"{username}さんが部屋から脱退しました"))

        # 参加者としての権限と関連状態を解除する
        db.execute(
            "DELETE FROM reactions WHERE room_id = ? AND username = ?",
            (room_id, username)
        )
        db.execute(
            "DELETE FROM raised_hands WHERE room_id = ? AND username = ?",
            (room_id, username)
        )
        db.execute(
            "DELETE FROM memberships WHERE room_id = ? AND username = ?",
            (room_id, username)
        )
        db.execute(
            "DELETE FROM join_requests WHERE room_id = ? AND username = ?",
            (room_id, username)
        )

    return jsonify({"message": "部屋から脱退したよ。再参加するにはもう一度申請してね"})




@app.route("/room/<room_id>")
def room_page(room_id):
    if not current_user():
        return render_template("index.html"), 401

    username = current_user()
    with connect_db() as db:
        room = db.execute(
            "SELECT id, name FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()

        if not room:
            return render_template(
                "chat.html",
                is_web_admin=is_web_admin(username)
            ), 404

        if not can_access_room(db, room_id, username):
            return render_template(
                "chat.html",
                is_web_admin=is_web_admin(username)
            ), 403

    return render_template(
        "room.txt", room_id=room["id"], room_name=room["name"]
    )

@app.route("/api/delete-room", methods=["POST"])
def delete_room():
    error = require_login()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    room_id = str(data.get("room_id", "")).strip()
    username = current_user()

    if not room_id:
        return jsonify({"error": "部屋IDを確認してね"}), 400

    with connect_db() as db:
        room = db.execute(
            "SELECT id, name FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()

        if not room:
            return jsonify({"error": "部屋はすでに削除されているよ"}), 404

        if not is_web_admin(username) and not is_room_admin(db, room_id, username):
            return jsonify({"error": "部屋の管理者だけが削除できるよ"}), 403

        recipients = db.execute("""
            SELECT username FROM memberships WHERE room_id = ?
            UNION
            SELECT username FROM join_requests WHERE room_id = ?
        """, (room_id, room_id)).fetchall()

        notice = f'管理者「{username}」が部屋「{room["name"]}」を削除しました。'

        for recipient in recipients:
            if recipient["username"] != username:
                db.execute("""
                    INSERT INTO user_notifications (username, content)
                    VALUES (?, ?)
                """, (recipient["username"], notice))

        # 関連データを先に削除
        for table in ("reactions", "raised_hands", "messages",
                      "memberships", "join_requests"):
            db.execute(
                f"DELETE FROM {table} WHERE room_id = ?", (room_id,)
            )

        db.execute("DELETE FROM rooms WHERE id = ?", (room_id,))

    return jsonify({"message": "部屋を削除したよ", "room_id": room_id})


@app.route("/api/notifications")
def notifications():
    error = require_login()
    if error:
        return error

    with connect_db() as db:
        rows = db.execute("""
            SELECT id, content, created_at
            FROM user_notifications
            WHERE username = ? AND is_read = 0
            ORDER BY id DESC LIMIT 50
        """, (current_user(),)).fetchall()

    return jsonify({"notifications": [dict(row) for row in rows]})


@app.route("/api/notifications/read", methods=["POST"])
def read_notifications():
    error = require_login()
    if error:
        return error

    with connect_db() as db:
        db.execute("""
            UPDATE user_notifications SET is_read = 1
            WHERE username = ?
        """, (current_user(),))

    return jsonify({"message": "通知を確認したよ"})


@app.route("/api/messages", methods=["GET", "POST"])
def messages():
    error = require_login()
    if error:
        return error

    username = current_user()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        room_id = str(data.get("room_id", "")).strip()
        content = str(data.get("content", "")).strip()

        if not content:
            return jsonify({"error": "メッセージを入力してね"}), 400
        if len(content) > 2000:
            return jsonify({"error": "メッセージは2000文字以内だよ"}), 400

        with connect_db() as db:
            if not can_access_room(db, room_id, username):
                return jsonify({"error": "参加しているルームだけ使えるよ"}), 403

            cursor = db.execute("""
                INSERT INTO messages (room_id, username, content)
                VALUES (?, ?, ?)
            """, (room_id, username, content))
            message_id = cursor.lastrowid

        return jsonify({"message": "送信したよ", "id": message_id})

    room_id = request.args.get("room_id", "").strip()

    with connect_db() as db:
        if not can_access_room(db, room_id, username):
            return jsonify({"error": "参加しているルームだけ見られるよ"}), 403

        rows = db.execute("""
            SELECT id, username, content, created_at
            FROM messages
            WHERE room_id = ?
            ORDER BY id
            LIMIT 200
        """, (room_id,)).fetchall()

        result = []
        for row in rows:
            item = dict(row)
            reactions = db.execute("""
                SELECT emoji, COUNT(*) AS count
                FROM reactions
                WHERE message_id = ?
                GROUP BY emoji
            """, (row["id"],)).fetchall()
            item["reactions"] = [dict(r) for r in reactions]
            result.append(item)

    return jsonify({"messages": result})


@app.route("/api/floating-emojis", methods=["GET", "POST"])
def floating_emojis():
    login_error = require_login()
    if login_error:
        return login_error

    username = current_user()

    with connect_db() as db:
        room_id = request.args.get("room_id", "") if request.method == "GET" else (request.get_json(silent=True) or {}).get("room_id", "")
        if not room_id or not can_access_room(db, room_id, username):
            return jsonify({"error": "この部屋には参加していないよ"}), 403

        # 表示時間は4秒。古い絵文字は削除する
        now = time.time()
        db.execute("DELETE FROM floating_emojis WHERE created_at < ?", (now - 4,))

        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            emoji = data.get("emoji", "")
            allowed = ["👍", "❤️", "😂", "🎉", "😮", "👏", "🔥", "✨", "💯", "🥳"]

            if emoji not in allowed:
                return jsonify({"error": "この絵文字は使えないよ"}), 400

            existing = db.execute("""
                SELECT id FROM floating_emojis
                WHERE room_id = ? AND username = ?
            """, (room_id, username)).fetchone()

            if existing:
                return jsonify({"error": "今の絵文字が消えるまで待ってね"}), 429

            db.execute("""
                INSERT INTO floating_emojis (room_id, username, emoji, created_at)
                VALUES (?, ?, ?, ?)
            """, (room_id, username, emoji, now))
            return jsonify({"ok": True})

        rows = db.execute("""
            SELECT id, username, emoji, created_at
            FROM floating_emojis
            WHERE room_id = ? AND created_at >= ?
            ORDER BY id
        """, (room_id, now - 4)).fetchall()

        return jsonify([dict(row) for row in rows])


@app.route("/api/react", methods=["POST"])
def react():
    error = require_login()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    room_id = str(data.get("room_id", "")).strip()
    emoji = str(data.get("emoji", "")).strip()

    try:
        message_id = int(data.get("message_id"))
    except (ValueError, TypeError):
        return jsonify({"error": "メッセージIDが正しくないよ"}), 400

    allowed_emojis = {"👍", "❤️", "😂", "🎉", "😮", "👏"}

    if emoji not in allowed_emojis:
        return jsonify({"error": "そのリアクションは使えないよ"}), 400

    with connect_db() as db:
        if not is_member(db, room_id, current_user()):
            return jsonify({"error": "参加しているルームだけ使えるよ"}), 403

        message = db.execute("""
            SELECT 1 FROM messages WHERE id = ? AND room_id = ?
        """, (message_id, room_id)).fetchone()

        if not message:
            return jsonify({"error": "メッセージが見つからないよ"}), 404

        existing = db.execute("""
            SELECT 1 FROM reactions
            WHERE message_id = ? AND username = ? AND emoji = ?
        """, (message_id, current_user(), emoji)).fetchone()

        if existing:
            db.execute("""
                DELETE FROM reactions
                WHERE message_id = ? AND username = ? AND emoji = ?
            """, (message_id, current_user(), emoji))
            active = False
        else:
            db.execute("""
                INSERT INTO reactions (room_id, message_id, username, emoji)
                VALUES (?, ?, ?, ?)
            """, (room_id, message_id, current_user(), emoji))
            active = True

    return jsonify({"active": active})


@app.route("/api/hand", methods=["GET", "POST"])
def hand():
    error = require_login()
    if error:
        return error

    username = current_user()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        room_id = str(data.get("room_id", "")).strip()

        with connect_db() as db:
            if not can_access_room(db, room_id, username):
                return jsonify({"error": "参加しているルームだけ使えるよ"}), 403

            existing = db.execute("""
                SELECT 1 FROM raised_hands
                WHERE room_id = ? AND username = ?
            """, (room_id, username)).fetchone()

            if existing:
                db.execute("""
                    DELETE FROM raised_hands
                    WHERE room_id = ? AND username = ?
                """, (room_id, username))
                raised = False
            else:
                db.execute("""
                    INSERT INTO raised_hands (room_id, username)
                    VALUES (?, ?)
                """, (room_id, username))
                raised = True

        return jsonify({"raised": raised})

    room_id = request.args.get("room_id", "").strip()

    with connect_db() as db:
        if not can_access_room(db, room_id, username):
            return jsonify({"error": "参加しているルームだけ見られるよ"}), 403

        rows = db.execute("""
            SELECT username, raised_at
            FROM raised_hands
            WHERE room_id = ?
            ORDER BY raised_at
        """, (room_id,)).fetchall()

    return jsonify({"hands": [dict(row) for row in rows]})


@app.route("/api/ban-user", methods=["POST"])
def ban_user():
    error = require_login()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    room_id = str(data.get("room_id", "")).strip()
    target = str(data.get("username", "")).strip()
    reason = str(data.get("reason", "")).strip()
    actor = current_user()

    if not room_id or not target or not reason:
        return jsonify({"error": "部屋ID・ユーザー名・BAN理由を入力してね"}), 400
    if len(reason) > 500:
        return jsonify({"error": "BAN理由は500文字以内だよ"}), 400
    if target == actor:
        return jsonify({"error": "自分自身はBANできないよ"}), 400

    with connect_db() as db:
        if not is_room_admin(db, room_id, actor):
            return jsonify({"error": "この部屋の管理者だけがBANできるよ"}), 403

        room = db.execute(
            "SELECT id FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if not room:
            return jsonify({"error": "部屋が見つからないよ"}), 404

        target_admin = db.execute("""
            SELECT 1 FROM memberships
            WHERE room_id = ? AND username = ? AND role = 'admin'
        """, (room_id, target)).fetchone()
        if target_admin:
            return jsonify({"error": "部屋の管理者はBANできないよ"}), 403

        db.execute("""
            INSERT INTO room_bans (room_id, username, banned_by, reason)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(room_id, username)
            DO UPDATE SET banned_by = excluded.banned_by,
                          reason = excluded.reason,
                          created_at = CURRENT_TIMESTAMP
        """, (room_id, target, actor, reason))

        db.execute("""
            DELETE FROM memberships
            WHERE room_id = ? AND username = ?
        """, (room_id, target))

        db.execute("""
            DELETE FROM join_requests
            WHERE room_id = ? AND username = ?
        """, (room_id, target))

        db.execute("""
            DELETE FROM raised_hands
            WHERE room_id = ? AND username = ?
        """, (room_id, target))

        db.execute("""
            DELETE FROM reactions
            WHERE room_id = ? AND username = ?
        """, (room_id, target))

        # 部屋の他のメンバーにはBANの事実だけを通知
        recipients = db.execute("""
            SELECT username FROM memberships
            WHERE room_id = ? AND username != ?
        """, (room_id, target)).fetchall()

        for recipient in recipients:
            db.execute("""
                INSERT INTO user_notifications (username, content)
                VALUES (?, ?)
            """, (
                recipient["username"],
                f"ユーザー「{target}」がこの部屋からBANされたよ。"
            ))

        db.execute("""
            INSERT INTO user_notifications (username, content)
            SELECT ?, ?
            WHERE EXISTS (SELECT 1 FROM users WHERE username = ?)
        """, (
            target,
            f"部屋「{room_id}」への参加が禁止されたよ。理由：{reason}",
            target
        ))

    return jsonify({"message": f"{target} を理由付きでBANしたよ"})




@app.route("/api/members")
def list_members():
    error = require_login()
    if error:
        return error

    room_id = str(request.args.get("room_id", "")).strip()
    username = current_user()

    if not room_id:
        return jsonify({"error": "部屋IDを指定してね"}), 400

    with connect_db() as db:
        if not can_access_room(db, room_id, username):
            return jsonify({"error": "この部屋のメンバーだけが見られるよ"}), 403

        room = db.execute(
            "SELECT id FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if not room:
            return jsonify({"error": "部屋が見つからないよ"}), 404

        rows = db.execute("""
            SELECT username, role
            FROM memberships
            WHERE room_id = ?
            ORDER BY CASE WHEN role = 'admin' THEN 0 ELSE 1 END,
                     username COLLATE NOCASE
        """, (room_id,)).fetchall()

    return jsonify({"members": [dict(row) for row in rows]})



@app.route("/api/room-info")
def room_info():
    error = require_login()
    if error:
        return error
    room_id = str(request.args.get("room_id", "")).strip()
    username = current_user()
    with connect_db() as db:
        if not can_access_room(db, room_id, username):
            return jsonify({"error": "この部屋のメンバーだけ使えるよ"}), 403
        room_admin = is_room_admin(db, room_id, username)
    return jsonify({
        "username": username,
        "is_room_admin": room_admin,
        "is_web_admin": is_web_admin(username)
    })


@app.route("/api/delete-message", methods=["POST"])
def delete_message():
    error = require_login()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    room_id = str(data.get("room_id", "")).strip()
    username = current_user()
    try:
        message_id = int(data.get("message_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "メッセージIDが正しくないよ"}), 400

    with connect_db() as db:
        if not can_access_room(db, room_id, username):
            return jsonify({"error": "この部屋のメンバーだけ使えるよ"}), 403
        message = db.execute("""
            SELECT id, room_id, username, content, created_at
            FROM messages WHERE id = ? AND room_id = ?
        """, (message_id, room_id)).fetchone()
        if not message:
            return jsonify({"error": "メッセージが見つからないよ"}), 404
        if (message["username"] != username
            and not is_room_admin(db, room_id, username)
            and not is_web_admin(username)):
            return jsonify({"error": "自分のメッセージだけ削除できるよ"}), 403

        db.execute("""
            INSERT INTO deleted_messages
                (original_message_id, room_id, username, content,
                 created_at, deleted_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            message["id"], message["room_id"], message["username"],
            message["content"], message["created_at"], username
        ))
        db.execute("DELETE FROM reactions WHERE message_id = ?", (message_id,))
        db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    return jsonify({"message": "メッセージを削除したよ"})


@app.route("/api/deleted-messages")
def list_deleted_messages():
    error = require_login()
    if error:
        return error
    username = current_user()
    room_id = str(request.args.get("room_id", "")).strip()

    with connect_db() as db:
        if is_web_admin(username):
            if room_id:
                rows = db.execute("""
                    SELECT id, original_message_id, room_id, username, content,
                           created_at, deleted_by, deleted_at
                    FROM deleted_messages
                    WHERE room_id = ?
                    ORDER BY id DESC LIMIT 500
                """, (room_id,)).fetchall()
            else:
                rows = db.execute("""
                    SELECT id, original_message_id, room_id, username, content,
                           created_at, deleted_by, deleted_at
                    FROM deleted_messages
                    ORDER BY id DESC LIMIT 500
                """).fetchall()
        else:
            if not is_room_admin(db, room_id, username):
                return jsonify({"error": "削除履歴は部屋の管理者だけ見られるよ"}), 403
            rows = db.execute("""
                SELECT id, original_message_id, room_id, username, content,
                       created_at, deleted_by, deleted_at
                FROM deleted_messages
                WHERE room_id = ?
                ORDER BY id DESC LIMIT 500
            """, (room_id,)).fetchall()

    return jsonify({"messages": [dict(row) for row in rows]})


@app.route("/api/room-command", methods=["POST"])
def room_command():
    error = require_login()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    room_id = str(data.get("room_id", "")).strip()
    command = str(data.get("command", "")).strip()
    username = current_user()

    with connect_db() as db:
        if not is_member(db, room_id, username):
            return jsonify({"error": "この部屋のメンバーだけ使えるよ"}), 403
        if not is_room_admin(db, room_id, username):
            return jsonify({"error": "部屋の管理者だけコマンドを使えるよ"}), 403

        parts = command.split(maxsplit=2)
        if not parts:
            return jsonify({"error": "コマンドを入力してね"}), 400

        action = parts[0].upper()
        if action == "CLEAR":
            rows = db.execute("""
                SELECT id, room_id, username, content, created_at
                FROM messages WHERE room_id = ?
            """, (room_id,)).fetchall()
            for message in rows:
                db.execute("""
                    INSERT INTO deleted_messages
                        (original_message_id, room_id, username, content,
                         created_at, deleted_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    message["id"], message["room_id"], message["username"],
                    message["content"], message["created_at"], username
                ))
            db.execute("DELETE FROM reactions WHERE room_id = ?", (room_id,))
            db.execute("DELETE FROM messages WHERE room_id = ?", (room_id,))
            return jsonify({"message": f"メッセージを{len(rows)}件整理したよ。履歴には残っているよ。"})

        if action == "BAN":
            if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
                return jsonify({"error": "使い方：BAN ユーザー名 理由"}), 400
            target = parts[1].strip()
            reason = parts[2].strip()
            if target == username:
                return jsonify({"error": "自分自身はBANできないよ"}), 400
            target_member = db.execute("""
                SELECT role FROM memberships
                WHERE room_id = ? AND username = ?
            """, (room_id, target)).fetchone()
            if not target_member:
                return jsonify({"error": "そのユーザーは部屋にいないよ"}), 404
            if target_member["role"] == "admin":
                return jsonify({"error": "部屋の管理者はBANできないよ"}), 400

            db.execute("""
                INSERT INTO room_bans (room_id, username, banned_by, reason)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(room_id, username) DO UPDATE SET
                    banned_by = excluded.banned_by,
                    reason = excluded.reason,
                    created_at = CURRENT_TIMESTAMP
            """, (room_id, target, username, reason))
            db.execute("DELETE FROM memberships WHERE room_id = ? AND username = ?", (room_id, target))
            db.execute("DELETE FROM join_requests WHERE room_id = ? AND username = ?", (room_id, target))
            db.execute("DELETE FROM raised_hands WHERE room_id = ? AND username = ?", (room_id, target))
            db.execute("DELETE FROM reactions WHERE room_id = ? AND username = ?", (room_id, target))

            # 理由はBANされた本人と管理者向け通知にだけ含める
            db.execute("""
                INSERT INTO user_notifications (username, content)
                VALUES (?, ?)
            """, (target, f"部屋「{room_id}」からBANされたよ。理由：{reason}"))

            other_members = db.execute("""
                SELECT username FROM memberships
                WHERE room_id = ? AND username != ?
            """, (room_id, target)).fetchall()
            for member in other_members:
                db.execute("""
                    INSERT INTO user_notifications (username, content)
                    VALUES (?, ?)
                """, (member["username"], f"この部屋で {target} がBANされたよ。"))

            return jsonify({"message": f"{target} をBANしたよ。理由は他の参加者には表示していないよ。"})

        return jsonify({"error": "使えるコマンドは CLEAR と BAN だよ"}), 400


if __name__ == "__main__":
    app.run(debug=True, port=5000)
