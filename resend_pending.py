# resend_pending.py
import sqlite3, os, smtplib, ssl

DB = os.environ.get('DB_PATH', 'licenses.db')

smtp_host = "smtp.gmail.com"
smtp_port = 587
user = "liv588lbx@gmail.com"
password = "jetw kpsm liwp nxtb"
from_addr = "liv588lbx@gmail.com"

conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("SELECT rowid, token, email FROM tokens WHERE status='pending' OR used=0")
rows = cur.fetchall()
if not rows:
    print("No hay tokens pendientes.")
else:
    context = ssl.create_default_context()
    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(user, password)
    except Exception as e:
        print("ERROR conectando SMTP:", type(e).__name__, str(e))
        raise SystemExit(1)

    for row in rows:
        rowid, token, email = row
        body = f"Subject: Tu token\n\nTu token: {token}\n"
        try:
            server.sendmail(from_addr, [email], body)
            # Marcamos como enviado cambiando status a 'sent'
            cur.execute("UPDATE tokens SET status='sent' WHERE rowid=?", (rowid,))
            print(f"Enviado a {email} (rowid {rowid})")
        except Exception as e:
            print(f"Error enviando a {email} (rowid {rowid}):", type(e).__name__, str(e))

    conn.commit()
    try:
        server.quit()
    except:
        pass

conn.close()
