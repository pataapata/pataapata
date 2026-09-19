from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
import sqlite3, os, secrets
from urllib.parse import quote
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "pata_a_pata.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PATA_SECRET_KEY", "cambiar-esta-clave-en-produccion")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

ALLOWED_IMAGES = {"png", "jpg", "jpeg", "gif", "webp"}
INSTAGRAM_URL = "https://www.instagram.com/"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Tenés que iniciar sesión para continuar.", "warning")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    u = conn.execute("SELECT * FROM usuarios WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return u

@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "instagram_url": INSTAGRAM_URL,
        "is_admin": bool(session.get("is_admin")),
    }

def ensure_column(conn, table, column, definition):
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        usuario TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        telefono TEXT,
        zona TEXT,
        familiar1_nombre TEXT,
        familiar1_telefono TEXT,
        familiar2_nombre TEXT,
        familiar2_telefono TEXT,
        veterinario_confianza TEXT,
        veterinario_telefono TEXT,
        activo INTEGER NOT NULL DEFAULT 1,
        is_admin INTEGER NOT NULL DEFAULT 0,
        creado_en TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS mascotas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER NOT NULL,
        nombre TEXT NOT NULL,
        especie TEXT NOT NULL,
        raza TEXT,
        sexo TEXT,
        nacimiento TEXT,
        color TEXT,
        peso REAL,
        castrado TEXT,
        observaciones TEXT,
        foto TEXT DEFAULT 'mascota.svg',
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS vacunas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mascota_id INTEGER NOT NULL,
        vacuna TEXT NOT NULL,
        fecha TEXT NOT NULL,
        proxima_fecha TEXT,
        veterinario TEXT,
        observaciones TEXT,
        FOREIGN KEY(mascota_id) REFERENCES mascotas(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS controles_salud (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mascota_id INTEGER NOT NULL,
        fecha TEXT NOT NULL,
        tipo TEXT NOT NULL,
        veterinario TEXT,
        observaciones TEXT,
        FOREIGN KEY(mascota_id) REFERENCES mascotas(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS desparasitaciones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mascota_id INTEGER NOT NULL,
        fecha TEXT NOT NULL,
        producto TEXT,
        proxima_fecha TEXT,
        veterinario TEXT,
        observaciones TEXT,
        FOREIGN KEY(mascota_id) REFERENCES mascotas(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS operaciones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mascota_id INTEGER NOT NULL,
        fecha TEXT NOT NULL,
        operacion TEXT NOT NULL,
        veterinario TEXT,
        observaciones TEXT,
        FOREIGN KEY(mascota_id) REFERENCES mascotas(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS publicaciones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER NOT NULL,
        texto TEXT NOT NULL,
        foto TEXT,
        creado_en TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS comentarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        publicacion_id INTEGER NOT NULL,
        usuario_id INTEGER NOT NULL,
        texto TEXT NOT NULL,
        creado_en TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(publicacion_id) REFERENCES publicaciones(id) ON DELETE CASCADE,
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS encuentros (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL,
        fecha TEXT NOT NULL,
        hora TEXT NOT NULL,
        lugar TEXT NOT NULL,
        descripcion TEXT,
        creado_por INTEGER,
        FOREIGN KEY(creado_por) REFERENCES usuarios(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS veterinarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        telefono TEXT,
        direccion TEXT,
        zona TEXT,
        especialidad TEXT
    );
    CREATE TABLE IF NOT EXISTS lugares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        categoria TEXT NOT NULL,
        direccion TEXT,
        zona TEXT,
        telefono TEXT
    );
    CREATE TABLE IF NOT EXISTS profesionales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        tipo TEXT NOT NULL,
        zona TEXT,
        telefono TEXT,
        disponibilidad TEXT
    );
    CREATE TABLE IF NOT EXISTS carrusel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT NOT NULL,
        texto TEXT,
        imagen TEXT NOT NULL,
        enlace TEXT,
        creado_en TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS mascota_del_mes (
        id INTEGER PRIMARY KEY CHECK (id=1),
        mascota_id INTEGER,
        periodo TEXT NOT NULL,
        FOREIGN KEY(mascota_id) REFERENCES mascotas(id) ON DELETE SET NULL
    );
    """)
    # Migración segura para bases creadas con versiones anteriores.
    ensure_column(conn, "mascotas", "veterinario_cabecera", "TEXT")
    ensure_column(conn, "mascotas", "veterinario_cabecera_telefono", "TEXT")
    conn.commit()
    if conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        admin_hash = generate_password_hash("admin123")
        demo_hash = generate_password_hash("demo123")
        conn.execute("""INSERT INTO usuarios
            (nombre,usuario,password_hash,telefono,zona,is_admin)
            VALUES (?,?,?,?,?,1)""",
            ("Administrador", "admin", admin_hash, "11 0000-0000", "San Miguel"))
        conn.execute("""INSERT INTO usuarios
            (nombre,usuario,password_hash,telefono,zona,familiar1_nombre,familiar1_telefono,
             familiar2_nombre,familiar2_telefono,veterinario_confianza,veterinario_telefono)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            ("Usuario Demo", "demo", demo_hash, "11 5555-0000", "San Miguel",
             "Ana Demo", "11 5555-1111", "Juan Demo", "11 5555-2222",
             "Dra. Paula González", "11 4444-1122"))
        uid = conn.execute("SELECT id FROM usuarios WHERE usuario='demo'").fetchone()["id"]
        conn.execute("""INSERT INTO mascotas
            (usuario_id,nombre,especie,raza,sexo,nacimiento,color,peso,castrado,observaciones)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (uid,"Luna","Perro","Mestiza","Hembra","2022-05-14","Marrón y blanca",
             12.5,"Sí","Muy sociable. Le encanta pasear y jugar."))
        mid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("""INSERT INTO vacunas
            (mascota_id,vacuna,fecha,proxima_fecha,veterinario,observaciones)
            VALUES (?,?,?,?,?,?)""",
            (mid,"Antirrábica","2026-03-20","2027-03-20","Dra. Paula González","Aplicación anual"))
        conn.executemany("""INSERT INTO veterinarios
            (nombre,telefono,direccion,zona,especialidad) VALUES (?,?,?,?,?)""", [
            ("Dra. Paula González","11 4444-1122","Av. Balbín 1234","San Miguel","Clínica general"),
            ("Centro Veterinario Norte","11 4444-7788","Av. Perón 2450","San Miguel","Guardia y clínica")
        ])
        conn.executemany("""INSERT INTO lugares
            (nombre,categoria,direccion,zona,telefono) VALUES (?,?,?,?,?)""", [
            ("Plaza de las Mascotas","Esparcimiento","Plaza principal","San Miguel",""),
            ("Pet Market San Miguel","Alimentos","Av. Perón 1800","San Miguel","11 4333-2211"),
            ("Café Huellitas","Pet Friendly","Paunero 900","San Miguel","11 4222-1100"),
            ("Centro Municipal de Vacunación","Vacunación","Sarmiento 500","San Miguel","11 4555-6677")
        ])
        conn.executemany("""INSERT INTO profesionales
            (nombre,tipo,zona,telefono,disponibilidad) VALUES (?,?,?,?,?)""", [
            ("María Paseos","Paseador/a","San Miguel","11 6000-1111","Lun a Vie 9 a 18"),
            ("Huellas en Casa","Cuidador/a","San Miguel","11 6000-2222","Todos los días")
        ])
        conn.execute("""INSERT INTO encuentros
            (titulo,fecha,hora,lugar,descripcion,creado_por)
            VALUES (?,?,?,?,?,?)""",
            ("Encuentro Pata a Pata","2026-09-20","16:00","Plaza de las Mascotas",
             "Mate, charla y juegos para mascotas sociables.",uid))
        conn.execute("""INSERT INTO publicaciones (usuario_id,texto)
                        VALUES (?,?)""",
                     (uid,"¡Bienvenidos a Pata a Pata! Compartamos fotos, historias y encuentros."))
        conn.commit()
    conn.close()

def save_image(file):
    if not file or not file.filename:
        return None
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_IMAGES:
        raise ValueError("Formato de imagen no permitido.")
    name = secure_filename(file.filename)
    stem = os.path.splitext(name)[0][:40] or "imagen"
    filename = f"{stem}_{secrets.token_hex(6)}.{ext}"
    file.save(os.path.join(UPLOAD_DIR, filename))
    return filename

@app.route("/")
def inicio():
    conn = get_db()
    slides = conn.execute("SELECT * FROM carrusel ORDER BY id DESC").fetchall()
    mascotas = []
    if session.get("user_id"):
        mascotas = conn.execute("SELECT * FROM mascotas WHERE usuario_id=? ORDER BY nombre", (session["user_id"],)).fetchall()
    else:
        mascotas = conn.execute("SELECT * FROM mascotas ORDER BY id LIMIT 3").fetchall()
    periodo = __import__("datetime").datetime.now().strftime("%Y-%m")
    mascota_mes = conn.execute("""SELECT m.*, u.nombre AS responsable_nombre
        FROM mascota_del_mes md
        LEFT JOIN mascotas m ON m.id=md.mascota_id
        LEFT JOIN usuarios u ON u.id=m.usuario_id
        WHERE md.id=1 AND md.periodo=?""", (periodo,)).fetchone()
    conn.close()
    return render_template("inicio.html", slides=slides, mascotas=mascotas, mascota_mes=mascota_mes)

@app.route("/registro", methods=["GET","POST"])
def registro():
    if request.method == "POST":
        nombre = request.form.get("nombre","").strip()
        usuario = request.form.get("usuario","").strip().lower()
        password = request.form.get("password","")
        telefono = request.form.get("telefono","").strip()
        zona = request.form.get("zona","").strip()
        if not nombre or not usuario or not password:
            flash("Completá nombre, usuario y contraseña.", "warning")
            return render_template("registro.html")
        conn = get_db()
        try:
            conn.execute("""INSERT INTO usuarios(nombre,usuario,password_hash,telefono,zona)
                            VALUES (?,?,?,?,?)""",
                         (nombre,usuario,generate_password_hash(password),telefono,zona))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Ese nombre de usuario ya existe.", "warning")
            return render_template("registro.html")
        conn.close()
        flash("Cuenta creada. Ahora podés iniciar sesión.", "success")
        return redirect(url_for("login"))
    return render_template("registro.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario","").strip().lower()
        password = request.form.get("password","")
        conn = get_db()
        u = conn.execute("SELECT * FROM usuarios WHERE usuario=?", (usuario,)).fetchone()
        conn.close()
        if not u or not check_password_hash(u["password_hash"], password):
            flash("Usuario o contraseña incorrectos.", "warning")
            return render_template("login.html")
        if not u["activo"]:
            flash("Esta cuenta está suspendida.", "warning")
            return render_template("login.html")
        session.clear()
        session["user_id"] = u["id"]
        session["is_admin"] = bool(u["is_admin"])
        flash("Sesión iniciada.", "success")
        return redirect(request.args.get("next") or url_for("inicio"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("inicio"))

@app.route("/mi_perfil", methods=["GET","POST"])
@login_required
def mi_perfil():
    conn = get_db()
    if request.method == "POST":
        conn.execute("""UPDATE usuarios SET nombre=?,telefono=?,zona=?,
                        familiar1_nombre=?,familiar1_telefono=?,familiar2_nombre=?,
                        familiar2_telefono=?,veterinario_confianza=?,veterinario_telefono=?
                        WHERE id=?""",
            (request.form.get("nombre","").strip(),request.form.get("telefono","").strip(),
             request.form.get("zona","").strip(),request.form.get("familiar1_nombre","").strip(),
             request.form.get("familiar1_telefono","").strip(),request.form.get("familiar2_nombre","").strip(),
             request.form.get("familiar2_telefono","").strip(),request.form.get("veterinario_confianza","").strip(),
             request.form.get("veterinario_telefono","").strip(),session["user_id"]))
        conn.commit()
        flash("Perfil actualizado.", "success")
    u = conn.execute("SELECT * FROM usuarios WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return render_template("perfil.html", usuario=u)

@app.route("/mascotas")
@login_required
def mascotas():
    conn = get_db()
    rows = conn.execute("SELECT * FROM mascotas WHERE usuario_id=? ORDER BY nombre",
                        (session["user_id"],)).fetchall()
    conn.close()
    return render_template("mascotas.html", mascotas=rows)

@app.route("/nueva_mascota", methods=["GET","POST"])
@login_required
def nueva_mascota():
    if request.method == "POST":
        try:
            foto = save_image(request.files.get("foto")) or "mascota.svg"
        except ValueError as e:
            flash(str(e), "warning")
            return render_template("nueva_mascota.html")
        conn = get_db()
        conn.execute("""INSERT INTO mascotas
            (usuario_id,nombre,especie,raza,sexo,nacimiento,color,peso,castrado,observaciones,foto)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (session["user_id"],request.form["nombre"],request.form["especie"],
             request.form.get("raza",""),request.form.get("sexo",""),request.form.get("nacimiento",""),
             request.form.get("color",""),request.form.get("peso") or None,request.form.get("castrado",""),
             request.form.get("observaciones",""),foto))
        conn.commit(); conn.close()
        flash("Mascota agregada correctamente.", "success")
        return redirect(url_for("mascotas"))
    return render_template("nueva_mascota.html")

@app.route("/mascota/<int:mascota_id>")
@login_required
def mascota(mascota_id):
    conn = get_db()
    m = conn.execute("SELECT * FROM mascotas WHERE id=? AND usuario_id=?",
                     (mascota_id,session["user_id"])).fetchone()
    vacunas = conn.execute("SELECT * FROM vacunas WHERE mascota_id=? ORDER BY fecha DESC",
                           (mascota_id,)).fetchall() if m else []
    controles = conn.execute("SELECT * FROM controles_salud WHERE mascota_id=? ORDER BY fecha DESC, id DESC",
                             (mascota_id,)).fetchall() if m else []
    desparasitaciones = conn.execute("SELECT * FROM desparasitaciones WHERE mascota_id=? ORDER BY fecha DESC, id DESC",
                                     (mascota_id,)).fetchall() if m else []
    operaciones = conn.execute("SELECT * FROM operaciones WHERE mascota_id=? ORDER BY fecha DESC, id DESC",
                               (mascota_id,)).fetchall() if m else []
    conn.close()
    if not m: abort(404)
    return render_template("mascota.html", mascota=m, vacunas=vacunas, controles=controles,
                           desparasitaciones=desparasitaciones, operaciones=operaciones)

@app.route("/mascota/<int:mascota_id>/libreta", methods=["GET", "POST"])
@login_required
def libreta_mascota(mascota_id):
    conn = get_db()
    m = conn.execute("SELECT * FROM mascotas WHERE id=? AND usuario_id=?",
                     (mascota_id, session["user_id"])).fetchone()
    if not m:
        conn.close(); abort(404)
    if request.method == "POST":
        veterinario = request.form.get("veterinario_cabecera", "").strip()
        veterinario_tel = request.form.get("veterinario_cabecera_telefono", "").strip()
        conn.execute("UPDATE mascotas SET veterinario_cabecera=?, veterinario_cabecera_telefono=? WHERE id=?",
                     (veterinario, veterinario_tel, mascota_id))

        # Se permite cargar uno o varios registros desde la misma pantalla.
        if request.form.get("vacuna") and request.form.get("vacuna_fecha"):
            conn.execute("INSERT INTO vacunas(mascota_id,vacuna,fecha,proxima_fecha,veterinario,observaciones) VALUES (?,?,?,?,?,?)",
                         (mascota_id, request.form["vacuna"].strip(), request.form["vacuna_fecha"],
                          request.form.get("vacuna_proxima") or None, request.form.get("vacuna_veterinario", "").strip(),
                          request.form.get("vacuna_observaciones", "").strip()))
        if request.form.get("control_tipo") and request.form.get("control_fecha"):
            conn.execute("INSERT INTO controles_salud(mascota_id,fecha,tipo,veterinario,observaciones) VALUES (?,?,?,?,?)",
                         (mascota_id, request.form["control_fecha"], request.form["control_tipo"].strip(),
                          request.form.get("control_veterinario", "").strip(), request.form.get("control_observaciones", "").strip()))
        if request.form.get("desparasitacion_fecha"):
            conn.execute("INSERT INTO desparasitaciones(mascota_id,fecha,producto,proxima_fecha,veterinario,observaciones) VALUES (?,?,?,?,?,?)",
                         (mascota_id, request.form["desparasitacion_fecha"], request.form.get("desparasitacion_producto", "").strip(),
                          request.form.get("desparasitacion_proxima") or None, request.form.get("desparasitacion_veterinario", "").strip(),
                          request.form.get("desparasitacion_observaciones", "").strip()))
        if request.form.get("operacion") and request.form.get("operacion_fecha"):
            conn.execute("INSERT INTO operaciones(mascota_id,fecha,operacion,veterinario,observaciones) VALUES (?,?,?,?,?)",
                         (mascota_id, request.form["operacion_fecha"], request.form["operacion"].strip(),
                          request.form.get("operacion_veterinario", "").strip(), request.form.get("operacion_observaciones", "").strip()))
        conn.commit(); conn.close()
        flash("Libreta sanitaria actualizada.", "success")
        return redirect(url_for("libreta_mascota", mascota_id=mascota_id))

    vacunas = conn.execute("SELECT * FROM vacunas WHERE mascota_id=? ORDER BY fecha DESC", (mascota_id,)).fetchall()
    controles = conn.execute("SELECT * FROM controles_salud WHERE mascota_id=? ORDER BY fecha DESC, id DESC", (mascota_id,)).fetchall()
    desparasitaciones = conn.execute("SELECT * FROM desparasitaciones WHERE mascota_id=? ORDER BY fecha DESC, id DESC", (mascota_id,)).fetchall()
    operaciones = conn.execute("SELECT * FROM operaciones WHERE mascota_id=? ORDER BY fecha DESC, id DESC", (mascota_id,)).fetchall()
    conn.close()
    return render_template("libreta.html", mascota=m, vacunas=vacunas, controles=controles,
                           desparasitaciones=desparasitaciones, operaciones=operaciones)

@app.post("/mascota/<int:mascota_id>/libreta/<tipo>/<int:registro_id>/delete")
@login_required
def eliminar_registro_libreta(mascota_id, tipo, registro_id):
    tablas = {"vacuna": "vacunas", "control": "controles_salud", "desparasitacion": "desparasitaciones", "operacion": "operaciones"}
    tabla = tablas.get(tipo)
    if not tabla:
        abort(404)
    conn = get_db()
    existe = conn.execute(f"SELECT id FROM {tabla} WHERE id=? AND mascota_id=?", (registro_id, mascota_id)).fetchone()
    mascota_ok = conn.execute("SELECT id FROM mascotas WHERE id=? AND usuario_id=?", (mascota_id, session["user_id"])).fetchone()
    if existe and mascota_ok:
        conn.execute(f"DELETE FROM {tabla} WHERE id=?", (registro_id,))
        conn.commit()
        flash("Registro eliminado de la libreta.", "success")
    conn.close()
    return redirect(url_for("libreta_mascota", mascota_id=mascota_id))

@app.route("/salud")
@login_required
def salud():
    conn = get_db()
    pets = conn.execute("SELECT * FROM mascotas WHERE usuario_id=? ORDER BY nombre", (session["user_id"],)).fetchall()
    data = []
    for pet in pets:
        vacunas = conn.execute("SELECT * FROM vacunas WHERE mascota_id=? ORDER BY fecha DESC", (pet["id"],)).fetchall()
        controles = conn.execute("SELECT * FROM controles_salud WHERE mascota_id=? ORDER BY fecha DESC, id DESC", (pet["id"],)).fetchall()
        desparasitaciones = conn.execute("SELECT * FROM desparasitaciones WHERE mascota_id=? ORDER BY fecha DESC, id DESC", (pet["id"],)).fetchall()
        operaciones = conn.execute("SELECT * FROM operaciones WHERE mascota_id=? ORDER BY fecha DESC, id DESC", (pet["id"],)).fetchall()
        data.append({"mascota": pet, "vacunas": vacunas, "controles": controles,
                     "desparasitaciones": desparasitaciones, "operaciones": operaciones})
    conn.close()
    return render_template("salud.html", mascotas_salud=data)

@app.route("/veterinarios")
@login_required
def veterinarios():
    conn=get_db(); rows=conn.execute("SELECT * FROM veterinarios ORDER BY nombre").fetchall(); conn.close()
    return render_template("veterinarios.html", veterinarios=rows)

@app.route("/lugares")
@login_required
def lugares():
    categoria=request.args.get("categoria","")
    conn=get_db()
    rows=conn.execute("SELECT * FROM lugares WHERE categoria=? ORDER BY nombre",(categoria,)).fetchall() if categoria else conn.execute("SELECT * FROM lugares ORDER BY categoria,nombre").fetchall()
    conn.close()
    return render_template("lugares.html",lugares=rows,categoria=categoria)

@app.route("/profesionales")
@login_required
def profesionales():
    tipo=request.args.get("tipo","")
    conn=get_db()
    rows=conn.execute("SELECT * FROM profesionales WHERE tipo=? ORDER BY nombre",(tipo,)).fetchall() if tipo else conn.execute("SELECT * FROM profesionales ORDER BY tipo,nombre").fetchall()
    conn.close()
    return render_template("profesionales.html",profesionales=rows,tipo=tipo)

def whatsapp_number(phone):
    """Convierte teléfonos argentinos habituales a formato internacional para wa.me."""
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    if not digits:
        return ""
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("54"):
        # WhatsApp usa 9 para móviles argentinos en formato internacional.
        if not digits.startswith("549") and len(digits) >= 12:
            digits = "549" + digits[2:]
        return digits
    if digits.startswith("0"):
        digits = digits[1:]
    # Si el usuario cargó un móvil argentino local (ej. 11 5555-1111).
    if digits.startswith("15") and len(digits) > 10:
        digits = digits[2:]
    if len(digits) == 10:
        return "549" + digits
    return "54" + digits

def build_whatsapp_message(usuario, mascotas, registros):
    lines = [
        "🐾 PATA A PATA – INFORMACIÓN DE EMERGENCIA",
        "",
        f"Responsable: {usuario['nombre']}",
        f"Teléfono: {usuario['telefono'] or 'No informado'}",
        f"Zona: {usuario['zona'] or 'No informada'}",
        "",
        "INFORMACIÓN DE LA/S MASCOTA/S:"
    ]
    for m in mascotas:
        lines += [
            "",
            f"🐶 {m['nombre']}",
            f"Especie: {m['especie'] or 'No informada'}",
            f"Raza: {m['raza'] or 'No informada'}",
            f"Sexo: {m['sexo'] or 'No informado'}",
            f"Nacimiento: {m['nacimiento'] or 'No informado'}",
            f"Color: {m['color'] or 'No informado'}",
            f"Peso: {str(m['peso']) + ' kg' if m['peso'] else 'No informado'}",
            f"Castrado/a: {m['castrado'] or 'No informado'}",
            f"Observaciones: {m['observaciones'] or 'Sin observaciones'}",
            f"Veterinaria de cabecera: {m['veterinario_cabecera'] or 'No informada'}",
            f"Tel. veterinaria de cabecera: {m['veterinario_cabecera_telefono'] or 'No informado'}",
        ]
        r = registros.get(m['id'], {})
        vacunas = r.get('vacunas', [])
        controles = r.get('controles', [])
        desparasitaciones = r.get('desparasitaciones', [])
        operaciones = r.get('operaciones', [])
        lines.append("Vacunas:")
        lines.extend([f"- {v['vacuna']} | {v['fecha']} | Próxima: {v['proxima_fecha'] or '—'} | {v['veterinario'] or 'Veterinario no indicado'} | {v['observaciones'] or ''}" for v in vacunas] or ["- Sin registros"])
        lines.append("Controles:")
        lines.extend([f"- {c['tipo']} | {c['fecha']} | {c['veterinario'] or 'Veterinario no indicado'} | {c['observaciones'] or ''}" for c in controles] or ["- Sin registros"])
        lines.append("Desparasitaciones:")
        lines.extend([f"- {d['producto'] or 'Desparasitación'} | {d['fecha']} | Próxima: {d['proxima_fecha'] or '—'} | {d['veterinario'] or 'Veterinario no indicado'} | {d['observaciones'] or ''}" for d in desparasitaciones] or ["- Sin registros"])
        lines.append("Operaciones/cirugías:")
        lines.extend([f"- {o['operacion']} | {o['fecha']} | {o['veterinario'] or 'Veterinario no indicado'} | {o['observaciones'] or ''}" for o in operaciones] or ["- Sin registros"])
    lines += [
        "",
        "Contacto familiar 1: " + (usuario['familiar1_nombre'] or 'No informado') + " – " + (usuario['familiar1_telefono'] or 'No informado'),
        "Contacto familiar 2: " + (usuario['familiar2_nombre'] or 'No informado') + " – " + (usuario['familiar2_telefono'] or 'No informado'),
        "Veterinario/a de confianza: " + (usuario['veterinario_confianza'] or 'No informado') + " – " + (usuario['veterinario_telefono'] or 'No informado'),
    ]
    return "\n".join(lines)

@app.route("/auxilio")
@login_required
def auxilio():
    conn=get_db()
    u=conn.execute("SELECT * FROM usuarios WHERE id=?",(session["user_id"],)).fetchone()
    mascotas=conn.execute("SELECT * FROM mascotas WHERE usuario_id=? ORDER BY nombre",(session["user_id"],)).fetchall()
    registros={}
    for m in mascotas:
        registros[m["id"]] = {
            "vacunas": conn.execute("SELECT * FROM vacunas WHERE mascota_id=? ORDER BY fecha DESC",(m["id"],)).fetchall(),
            "controles": conn.execute("SELECT * FROM controles_salud WHERE mascota_id=? ORDER BY fecha DESC, id DESC",(m["id"],)).fetchall(),
            "desparasitaciones": conn.execute("SELECT * FROM desparasitaciones WHERE mascota_id=? ORDER BY fecha DESC, id DESC",(m["id"],)).fetchall(),
            "operaciones": conn.execute("SELECT * FROM operaciones WHERE mascota_id=? ORDER BY fecha DESC, id DESC",(m["id"],)).fetchall(),
        }
    vets=conn.execute("SELECT * FROM veterinarios ORDER BY nombre").fetchall()
    mensaje=build_whatsapp_message(u, mascotas, registros)
    whatsapp_message=quote(mensaje)
    contactos=[]
    for nombre,telefono,tipo in [
        (u["familiar1_nombre"],u["familiar1_telefono"],"Familiar"),
        (u["familiar2_nombre"],u["familiar2_telefono"],"Familiar"),
        (u["veterinario_confianza"],u["veterinario_telefono"],"Veterinario/a de cabecera"),
    ]:
        if telefono:
            contactos.append({"nombre": nombre or tipo, "telefono": telefono, "tipo": tipo,
                              "tel_url": "tel:" + telefono,
                              "whatsapp_url": "https://wa.me/" + whatsapp_number(telefono) + "?text=" + whatsapp_message})
    conn.close()
    return render_template("auxilio.html",usuario=u,veterinarios=vets,contactos=contactos,hay_mascotas=bool(mascotas))

@app.route("/comunidad", methods=["GET","POST"])
@login_required
def comunidad():
    conn=get_db()
    if request.method=="POST":
        texto=request.form.get("texto","").strip()
        if not texto:
            flash("Escribí algo para publicar.", "warning")
        else:
            try: foto=save_image(request.files.get("foto"))
            except ValueError as e:
                flash(str(e),"warning"); foto=None
            if texto:
                conn.execute("INSERT INTO publicaciones(usuario_id,texto,foto) VALUES (?,?,?)",
                             (session["user_id"],texto,foto))
                conn.commit(); flash("Publicación compartida.", "success")
        conn.close()
        return redirect(url_for("comunidad"))
    posts=conn.execute("""SELECT p.*,u.nombre,u.usuario FROM publicaciones p
                          JOIN usuarios u ON u.id=p.usuario_id
                          WHERE u.activo=1 ORDER BY p.id DESC""").fetchall()
    comments={}
    for p in posts:
        comments[p["id"]]=conn.execute("""SELECT c.*,u.nombre,u.usuario FROM comentarios c
                                           JOIN usuarios u ON u.id=c.usuario_id
                                           WHERE c.publicacion_id=? AND u.activo=1 ORDER BY c.id""",
                                        (p["id"],)).fetchall()
    conn.close()
    return render_template("comunidad.html",posts=posts,comments=comments)

@app.post("/comunidad/<int:post_id>/comentario")
@login_required
def comentar(post_id):
    texto=request.form.get("texto","").strip()
    if texto:
        conn=get_db()
        exists=conn.execute("SELECT id FROM publicaciones WHERE id=?",(post_id,)).fetchone()
        if exists:
            conn.execute("INSERT INTO comentarios(publicacion_id,usuario_id,texto) VALUES (?,?,?)",
                         (post_id,session["user_id"],texto)); conn.commit()
        conn.close()
    return redirect(url_for("comunidad"))

@app.route("/encuentros")
@login_required
def encuentros():
    conn=get_db()
    rows=conn.execute("""SELECT e.*,u.nombre AS creador FROM encuentros e
                         LEFT JOIN usuarios u ON u.id=e.creado_por ORDER BY e.fecha,e.hora""").fetchall()
    conn.close()
    return render_template("encuentros.html",encuentros=rows)

@app.route("/nuevo_encuentro", methods=["GET","POST"])
@login_required
def nuevo_encuentro():
    if request.method=="POST":
        conn=get_db()
        conn.execute("""INSERT INTO encuentros(titulo,fecha,hora,lugar,descripcion,creado_por)
                        VALUES (?,?,?,?,?,?)""",
                     (request.form["titulo"],request.form["fecha"],request.form["hora"],
                      request.form["lugar"],request.form.get("descripcion",""),session["user_id"]))
        conn.commit(); conn.close()
        flash("Encuentro publicado.","success")
        return redirect(url_for("encuentros"))
    return render_template("nuevo_encuentro.html")

@app.route("/admin")
@admin_required
def admin():
    conn=get_db()
    users=conn.execute("SELECT id,nombre,usuario,telefono,zona,activo,is_admin,creado_en FROM usuarios ORDER BY id DESC").fetchall()
    comments=conn.execute("""SELECT c.id,c.texto,c.creado_en,u.nombre AS autor,p.texto AS publicacion
                             FROM comentarios c JOIN usuarios u ON u.id=c.usuario_id
                             JOIN publicaciones p ON p.id=c.publicacion_id
                             ORDER BY c.id DESC""").fetchall()
    slides=conn.execute("SELECT * FROM carrusel ORDER BY id DESC").fetchall()
    pets=conn.execute("""SELECT m.*,u.nombre AS responsable_nombre FROM mascotas m
                         JOIN usuarios u ON u.id=m.usuario_id ORDER BY m.nombre""").fetchall()
    periodo=__import__("datetime").datetime.now().strftime("%Y-%m")
    selected=conn.execute("SELECT mascota_id FROM mascota_del_mes WHERE id=1 AND periodo=?",(periodo,)).fetchone()
    mascota_mes_id=selected["mascota_id"] if selected else None
    conn.close()
    return render_template("admin.html",users=users,comments=comments,slides=slides,pets=pets,mascota_mes_id=mascota_mes_id)

@app.post("/admin/usuario/<int:user_id>/toggle")
@admin_required
def toggle_user(user_id):
    if user_id == session["user_id"]:
        flash("No podés suspender tu propia cuenta.","warning")
    else:
        conn=get_db()
        conn.execute("UPDATE usuarios SET activo=CASE activo WHEN 1 THEN 0 ELSE 1 END WHERE id=?",(user_id,))
        conn.commit(); conn.close()
        flash("Estado del usuario actualizado.","success")
    return redirect(url_for("admin"))

@app.post("/admin/usuario/<int:user_id>/delete")
@admin_required
def delete_user(user_id):
    if user_id == session["user_id"]:
        flash("No podés eliminar tu propia cuenta.","warning")
    else:
        conn=get_db(); conn.execute("DELETE FROM usuarios WHERE id=?",(user_id,)); conn.commit(); conn.close()
        flash("Usuario y sus datos eliminados.","success")
    return redirect(url_for("admin"))

@app.post("/admin/comentario/<int:comment_id>/delete")
@admin_required
def delete_comment(comment_id):
    conn=get_db(); conn.execute("DELETE FROM comentarios WHERE id=?",(comment_id,)); conn.commit(); conn.close()
    flash("Comentario eliminado.","success")
    return redirect(url_for("admin"))

@app.post("/admin/carrusel/add")
@admin_required
def add_slide():
    try:
        imagen=save_image(request.files.get("imagen"))
    except ValueError as e:
        flash(str(e),"warning"); return redirect(url_for("admin"))
    if not imagen:
        flash("Seleccioná una foto.","warning"); return redirect(url_for("admin"))
    conn=get_db()
    conn.execute("INSERT INTO carrusel(titulo,texto,imagen,enlace) VALUES (?,?,?,?)",("","",imagen,""))
    conn.commit(); conn.close()
    flash("Foto agregada al carrusel.","success")
    return redirect(url_for("admin"))

@app.post("/admin/mascota-del-mes")
@admin_required
def set_mascota_del_mes():
    mascota_id=request.form.get("mascota_id","").strip()
    periodo=__import__("datetime").datetime.now().strftime("%Y-%m")
    conn=get_db()
    if mascota_id:
        if not conn.execute("SELECT id FROM mascotas WHERE id=?",(mascota_id,)).fetchone():
            conn.close(); flash("La mascota seleccionada no existe.","warning"); return redirect(url_for("admin"))
        conn.execute("DELETE FROM mascota_del_mes WHERE id=1")
        conn.execute("INSERT INTO mascota_del_mes(id,mascota_id,periodo) VALUES (1,?,?)",(mascota_id,periodo))
        flash("Mascota del mes actualizada.","success")
    else:
        conn.execute("DELETE FROM mascota_del_mes WHERE id=1")
        flash("Se quitó la mascota del mes.","success")
    conn.commit(); conn.close()
    return redirect(url_for("admin"))

@app.post("/admin/carrusel/<int:slide_id>/delete")
@admin_required
def delete_slide(slide_id):
    conn=get_db(); s=conn.execute("SELECT imagen FROM carrusel WHERE id=?",(slide_id,)).fetchone()
    if s:
        conn.execute("DELETE FROM carrusel WHERE id=?",(slide_id,)); conn.commit()
        path=os.path.join(UPLOAD_DIR,s["imagen"])
        if os.path.exists(path): os.remove(path)
    conn.close()
    flash("Imagen eliminada del carrusel.","success")
    return redirect(url_for("admin"))

if __name__ == "__main__":
    init_db()
    print("\\n🐾 PATA A PATA V2")
    print("Abrí en tu navegador: http://127.0.0.1:5000\\n")
    app.run(debug=True)
