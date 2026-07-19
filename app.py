import os
import uuid

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g, abort
)
from flask_socketio import SocketIO, emit, join_room
from flask_wtf import CSRFProtect

from db import get_db, close_db, init_db, now_str, PRODUCT_REPORT_THRESHOLD, USER_REPORT_THRESHOLD, STARTING_BALANCE
from security import (
    hash_password, verify_password, validate_username, validate_password,
    validate_price, validate_amount, clean_text,
    login_required, admin_required,
    LOGIN_MAX_ATTEMPTS, LOGIN_LOCK_SECONDS,
    chat_rate_limiter, report_rate_limiter,
)

import time

app = Flask(__name__)

# SECRET_KEY: 운영 환경에서는 반드시 환경변수로 주입한다. 미설정 시 매 프로세스 재시작마다
# 새 값이 생성되어 기존 세션이 모두 무효화되므로, 실제 배포 시에는 고정값을 SECRET_KEY 환경변수로 지정할 것.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(32).hex()

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('FORCE_HTTPS', '0') == '1',
    PERMANENT_SESSION_LIFETIME=30 * 60,  # 30분 유휴 시 세션 만료
)

DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'

csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins=[])

app.teardown_appcontext(close_db)

MAX_CHAT_MESSAGE_LEN = 500
MAX_REPORT_REASON_LEN = 500
MAX_BIO_LEN = 500
MAX_TITLE_LEN = 100
MAX_DESC_LEN = 2000


@app.before_request
def make_session_permanent():
    session.permanent = True


# ---------------------------------------------------------------------------
# 기본 라우트
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# ---------------------------------------------------------------------------
# 회원가입 / 로그인 / 로그아웃
# ---------------------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not validate_username(username):
            flash('사용자명은 영문/숫자/밑줄(_)만 사용하여 3~20자로 입력해주세요.')
            return redirect(url_for('register'))
        if not validate_password(password):
            flash('비밀번호는 8~64자이며 영문, 숫자, 특수문자를 각 1개 이상 포함해야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        existing = db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()
        if existing is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO user (id, username, password_hash, bio, balance, created_at) "
            "VALUES (?, ?, ?, '', ?, ?)",
            (user_id, username, hash_password(password), STARTING_BALANCE, now_str())
        )
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        db = get_db()
        user = db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()
        now = time.time()
        if user is not None and user['lock_until'] > now:
            remaining = int(user['lock_until'] - now)
            flash(f'로그인 시도가 너무 많습니다. {remaining}초 후 다시 시도해주세요.')
            return redirect(url_for('login'))

        ok = user is not None and verify_password(user['password_hash'], password)

        if ok and user['is_banned']:
            flash('휴면 처리된 계정입니다. 관리자에게 문의해주세요.')
            return redirect(url_for('login'))

        if not ok:
            if user is not None:
                fails = user['failed_login_count'] + 1
                lock_until = now + LOGIN_LOCK_SECONDS if fails >= LOGIN_MAX_ATTEMPTS else 0
                db.execute(
                    "UPDATE user SET failed_login_count = ?, lock_until = ? WHERE id = ?",
                    (0 if lock_until else fails, lock_until, user['id'])
                )
                db.commit()
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

        db.execute("UPDATE user SET failed_login_count = 0, lock_until = 0 WHERE id = ?", (user['id'],))
        db.commit()
        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        flash('로그인 성공!')
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# 대시보드 / 검색
# ---------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    all_products = db.execute(
        "SELECT * FROM product WHERE status = 'active' ORDER BY created_at DESC"
    ).fetchall()
    return render_template('dashboard.html', products=all_products, user=g.current_user, query=None)


@app.route('/search')
@login_required
def search():
    q = clean_text(request.args.get('q', ''), 100)
    db = get_db()
    if q:
        like_q = '%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        products = db.execute(
            "SELECT * FROM product WHERE status = 'active' AND title LIKE ? ESCAPE '\\' "
            "ORDER BY created_at DESC",
            (like_q,)
        ).fetchall()
    else:
        products = []
    return render_template('dashboard.html', products=products, user=g.current_user, query=q)


# ---------------------------------------------------------------------------
# 프로필
# ---------------------------------------------------------------------------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action', 'bio')
        if action == 'bio':
            bio = clean_text(request.form.get('bio', ''), MAX_BIO_LEN)
            db.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, g.current_user['id']))
            db.commit()
            flash('프로필이 업데이트되었습니다.')
        elif action == 'password':
            # 민감 작업(비밀번호 변경)이므로 현재 비밀번호 재인증을 요구한다.
            current_password = request.form.get('current_password') or ''
            new_password = request.form.get('new_password') or ''
            if not verify_password(g.current_user['password_hash'], current_password):
                flash('현재 비밀번호가 일치하지 않습니다.')
                return redirect(url_for('profile'))
            if not validate_password(new_password):
                flash('새 비밀번호는 8~64자이며 영문, 숫자, 특수문자를 각 1개 이상 포함해야 합니다.')
                return redirect(url_for('profile'))
            db.execute("UPDATE user SET password_hash = ? WHERE id = ?",
                       (hash_password(new_password), g.current_user['id']))
            db.commit()
            flash('비밀번호가 변경되었습니다.')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=g.current_user)


@app.route('/user/<user_id>')
@login_required
def user_profile(user_id):
    db = get_db()
    target = db.execute("SELECT id, username, bio, is_banned, created_at FROM user WHERE id = ?",
                         (user_id,)).fetchone()
    if target is None:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    products = db.execute(
        "SELECT * FROM product WHERE seller_id = ? AND status = 'active' ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    return render_template('user_profile.html', target=target, products=products)


# ---------------------------------------------------------------------------
# 상품 관리
# ---------------------------------------------------------------------------
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        title = clean_text(request.form.get('title', ''), MAX_TITLE_LEN)
        description = clean_text(request.form.get('description', ''), MAX_DESC_LEN)
        price = validate_price(request.form.get('price', ''))

        if not title or not description:
            flash('제목과 설명을 입력해주세요.')
            return redirect(url_for('new_product'))
        if price is None:
            flash('가격은 0 이상의 숫자로 입력해주세요.')
            return redirect(url_for('new_product'))

        db = get_db()
        product_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO product (id, title, description, price, seller_id, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (product_id, title, description, price, g.current_user['id'], now_str())
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    seller = db.execute("SELECT id, username FROM user WHERE id = ?", (product['seller_id'],)).fetchone()
    is_owner = product['seller_id'] == g.current_user['id']
    return render_template('view_product.html', product=product, seller=seller, is_owner=is_owner)


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 소유자 확인: 본인 상품만 수정 가능
    if product['seller_id'] != g.current_user['id']:
        abort(403)

    if request.method == 'POST':
        title = clean_text(request.form.get('title', ''), MAX_TITLE_LEN)
        description = clean_text(request.form.get('description', ''), MAX_DESC_LEN)
        price = validate_price(request.form.get('price', ''))
        if not title or not description:
            flash('제목과 설명을 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        if price is None:
            flash('가격은 0 이상의 숫자로 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        db.execute("UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
                   (title, description, price, product_id))
        db.commit()
        flash('상품 정보가 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM product WHERE id = ?", (product_id,)).fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['seller_id'] != g.current_user['id']:
        abort(403)
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))


@app.route('/my/products')
@login_required
def my_products():
    db = get_db()
    products = db.execute(
        "SELECT * FROM product WHERE seller_id = ? ORDER BY created_at DESC",
        (g.current_user['id'],)
    ).fetchall()
    return render_template('my_products.html', products=products)


# ---------------------------------------------------------------------------
# 신고
# ---------------------------------------------------------------------------
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        target_type = request.form.get('target_type', '')
        target_id = clean_text(request.form.get('target_id', ''), 64)
        reason = clean_text(request.form.get('reason', ''), MAX_REPORT_REASON_LEN)

        if target_type not in ('user', 'product'):
            flash('신고 대상 종류를 선택해주세요.')
            return redirect(url_for('report'))
        if not target_id or not reason:
            flash('신고 대상과 사유를 입력해주세요.')
            return redirect(url_for('report'))

        db = get_db()
        if target_type == 'user':
            target = db.execute("SELECT id FROM user WHERE id = ?", (target_id,)).fetchone()
        else:
            target = db.execute("SELECT id FROM product WHERE id = ?", (target_id,)).fetchone()
        if target is None:
            flash('신고 대상을 찾을 수 없습니다.')
            return redirect(url_for('report'))

        if target_type == 'user' and target_id == g.current_user['id']:
            flash('본인은 신고할 수 없습니다.')
            return redirect(url_for('report'))

        # 신고 남용 방지: 사용자당 시간당 신고 횟수 제한
        if not report_rate_limiter.allow(g.current_user['id'], max_hits=10, window_seconds=3600):
            flash('신고 횟수 제한을 초과했습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())
        try:
            db.execute(
                "INSERT INTO report (id, reporter_id, target_type, target_id, reason, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (report_id, g.current_user['id'], target_type, target_id, reason, now_str())
            )
            db.commit()
        except Exception:
            db.rollback()
            flash('이미 동일한 대상을 신고하셨습니다.')
            return redirect(url_for('report'))

        _apply_report_threshold(db, target_type, target_id)
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    prefill_type = request.args.get('target_type', '')
    prefill_id = request.args.get('target_id', '')
    if prefill_type not in ('user', 'product'):
        prefill_type = ''
    return render_template('report.html', prefill_type=prefill_type, prefill_id=prefill_id)


def _apply_report_threshold(db, target_type, target_id):
    count = db.execute(
        "SELECT COUNT(*) AS c FROM report WHERE target_type = ? AND target_id = ?",
        (target_type, target_id)
    ).fetchone()['c']
    if target_type == 'product' and count >= PRODUCT_REPORT_THRESHOLD:
        db.execute("UPDATE product SET status = 'blocked' WHERE id = ? AND status = 'active'", (target_id,))
        db.commit()
    elif target_type == 'user' and count >= USER_REPORT_THRESHOLD:
        db.execute("UPDATE user SET is_banned = 1 WHERE id = ?", (target_id,))
        db.commit()


# ---------------------------------------------------------------------------
# 송금
# ---------------------------------------------------------------------------
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    if request.method == 'POST':
        to_username = (request.form.get('to_username') or '').strip()
        amount = validate_amount(request.form.get('amount', ''))
        password = request.form.get('password') or ''

        # 민감 작업(송금)이므로 현재 비밀번호 재인증을 요구한다.
        if not verify_password(g.current_user['password_hash'], password):
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('transfer'))
        if amount is None or amount <= 0:
            flash('올바른 송금액을 입력해주세요.')
            return redirect(url_for('transfer'))

        receiver = db.execute("SELECT * FROM user WHERE username = ?", (to_username,)).fetchone()
        if receiver is None:
            flash('받는 사람을 찾을 수 없습니다.')
            return redirect(url_for('transfer'))
        if receiver['id'] == g.current_user['id']:
            flash('본인에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))
        if receiver['is_banned']:
            flash('휴면 계정으로는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))
        if g.current_user['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        try:
            db.execute("BEGIN IMMEDIATE")
            sender_row = db.execute("SELECT balance FROM user WHERE id = ?", (g.current_user['id'],)).fetchone()
            if sender_row['balance'] < amount:
                raise ValueError('insufficient balance')
            db.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, g.current_user['id']))
            db.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
            db.execute(
                "INSERT INTO \"transaction\" (id, sender_id, receiver_id, amount, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), g.current_user['id'], receiver['id'], amount, now_str())
            )
            db.commit()
        except Exception:
            db.rollback()
            flash('송금 처리 중 오류가 발생했습니다.')
            return redirect(url_for('transfer'))

        flash(f'{to_username}님에게 {amount}원을 송금했습니다.')
        return redirect(url_for('transfer'))

    history = db.execute(
        "SELECT t.*, su.username AS sender_name, ru.username AS receiver_name "
        "FROM \"transaction\" t "
        "JOIN user su ON su.id = t.sender_id "
        "JOIN user ru ON ru.id = t.receiver_id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.created_at DESC LIMIT 50",
        (g.current_user['id'], g.current_user['id'])
    ).fetchall()
    return render_template('transfer.html', history=history)


# ---------------------------------------------------------------------------
# 1:1 채팅
# ---------------------------------------------------------------------------
def _dm_room(user_id_a, user_id_b):
    return 'dm:' + ':'.join(sorted([user_id_a, user_id_b]))


@app.route('/messages')
@login_required
def messages_list():
    db = get_db()
    # room 문자열('dm:<id_a>:<id_b>')에서 현재 사용자와 대화한 상대방 id를 추출한다.
    rooms = db.execute(
        "SELECT DISTINCT room FROM message WHERE room LIKE 'dm:%' AND room LIKE ?",
        ('%' + g.current_user['id'] + '%',)
    ).fetchall()
    partners = []
    seen = set()
    for r in rooms:
        ids = r['room'][3:].split(':')
        other_id = ids[0] if ids[1] == g.current_user['id'] else ids[1]
        if other_id in seen:
            continue
        seen.add(other_id)
        u = db.execute("SELECT id, username FROM user WHERE id = ?", (other_id,)).fetchone()
        if u:
            partners.append(u)
    return render_template('messages_list.html', partners=partners)


@app.route('/messages/<other_user_id>')
@login_required
def dm_chat(other_user_id):
    db = get_db()
    other = db.execute("SELECT id, username FROM user WHERE id = ?", (other_user_id,)).fetchone()
    if other is None:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('messages_list'))
    room = _dm_room(g.current_user['id'], other_user_id)
    history = db.execute(
        "SELECT m.*, u.username FROM message m JOIN user u ON u.id = m.sender_id "
        "WHERE m.room = ? ORDER BY m.created_at ASC LIMIT 200",
        (room,)
    ).fetchall()
    return render_template('dm_chat.html', other=other, room=room, history=history)


# ---------------------------------------------------------------------------
# 실시간 채팅 (Socket.IO)
# ---------------------------------------------------------------------------
@socketio.on('send_message')
def handle_send_message_event(data):
    if 'user_id' not in session:
        return
    db = get_db()
    user = db.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],)).fetchone()
    if user is None or user['is_banned']:
        return
    if not chat_rate_limiter.allow(user['id'], max_hits=5, window_seconds=10):
        return
    message = clean_text(data.get('message', ''), MAX_CHAT_MESSAGE_LEN)
    if not message:
        return
    emit('message', {
        'message_id': str(uuid.uuid4()),
        'username': user['username'],
        'message': message,
    }, broadcast=True)


@socketio.on('join_dm')
def handle_join_dm(data):
    if 'user_id' not in session:
        return
    other_id = data.get('other_id', '')
    room = _dm_room(session['user_id'], other_id)
    join_room(room)


@socketio.on('send_dm_message')
def handle_send_dm_message(data):
    if 'user_id' not in session:
        return
    db = get_db()
    user = db.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],)).fetchone()
    if user is None or user['is_banned']:
        return
    other_id = data.get('other_id', '')
    other = db.execute("SELECT id FROM user WHERE id = ?", (other_id,)).fetchone()
    if other is None:
        return
    if not chat_rate_limiter.allow(user['id'], max_hits=5, window_seconds=10):
        return
    message = clean_text(data.get('message', ''), MAX_CHAT_MESSAGE_LEN)
    if not message:
        return
    room = _dm_room(user['id'], other_id)
    message_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO message (id, room, sender_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (message_id, room, user['id'], message, now_str())
    )
    db.commit()
    emit('dm_message', {
        'message_id': message_id,
        'username': user['username'],
        'message': message,
    }, room=room)


# ---------------------------------------------------------------------------
# 관리자
# ---------------------------------------------------------------------------
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    stats = {
        'user_count': db.execute("SELECT COUNT(*) c FROM user").fetchone()['c'],
        'product_count': db.execute("SELECT COUNT(*) c FROM product").fetchone()['c'],
        'report_count': db.execute("SELECT COUNT(*) c FROM report").fetchone()['c'],
    }
    return render_template('admin/dashboard.html', stats=stats)


@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    users = db.execute("SELECT * FROM user ORDER BY created_at DESC").fetchall()
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/<user_id>/ban', methods=['POST'])
@admin_required
def admin_ban_user(user_id):
    db = get_db()
    db.execute("UPDATE user SET is_banned = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash('사용자를 휴면 처리했습니다.')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<user_id>/unban', methods=['POST'])
@admin_required
def admin_unban_user(user_id):
    db = get_db()
    db.execute("UPDATE user SET is_banned = 0, failed_login_count = 0, lock_until = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash('사용자 휴면을 해제했습니다.')
    return redirect(url_for('admin_users'))


@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    products = db.execute(
        "SELECT p.*, u.username AS seller_name FROM product p JOIN user u ON u.id = p.seller_id "
        "ORDER BY p.created_at DESC"
    ).fetchall()
    return render_template('admin/products.html', products=products)


@app.route('/admin/products/<product_id>/block', methods=['POST'])
@admin_required
def admin_block_product(product_id):
    db = get_db()
    db.execute("UPDATE product SET status = 'blocked' WHERE id = ?", (product_id,))
    db.commit()
    flash('상품을 차단했습니다.')
    return redirect(url_for('admin_products'))


@app.route('/admin/products/<product_id>/unblock', methods=['POST'])
@admin_required
def admin_unblock_product(product_id):
    db = get_db()
    db.execute("UPDATE product SET status = 'active' WHERE id = ?", (product_id,))
    db.commit()
    flash('상품 차단을 해제했습니다.')
    return redirect(url_for('admin_products'))


@app.route('/admin/products/<product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품을 삭제했습니다.')
    return redirect(url_for('admin_products'))


@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    reports = db.execute(
        "SELECT r.*, u.username AS reporter_name FROM report r JOIN user u ON u.id = r.reporter_id "
        "ORDER BY r.created_at DESC"
    ).fetchall()
    return render_template('admin/reports.html', reports=reports)


# ---------------------------------------------------------------------------
# CLI: 관리자 승격 (웹으로 노출하지 않고 서버 접근 권한이 있는 운영자만 실행 가능)
# ---------------------------------------------------------------------------
@app.cli.command('create-admin')
def create_admin_command():
    import click
    username = click.prompt('관리자로 승격할 사용자명')
    with app.app_context():
        db = get_db()
        user = db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()
        if user is None:
            click.echo(f'사용자 {username} 을(를) 찾을 수 없습니다. 먼저 회원가입을 진행해주세요.')
            return
        db.execute("UPDATE user SET is_admin = 1 WHERE id = ?", (user['id'],))
        db.commit()
        click.echo(f'{username} 을(를) 관리자로 승격했습니다.')


# ---------------------------------------------------------------------------
# 보안 헤더 & 에러 핸들러
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'"
    )
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    return response


@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def server_error(e):
    app.logger.exception('Internal server error')
    return render_template('errors/500.html'), 500


if __name__ == '__main__':
    init_db(app)
    # allow_unsafe_werkzeug: 이 프로젝트는 과제/로컬 테스트용 개발 서버로만 사용한다.
    # 실제 운영 배포 시에는 eventlet/gunicorn 등 프로덕션 WSGI 서버를 사용할 것.
    socketio.run(app, debug=DEBUG, allow_unsafe_werkzeug=True)
