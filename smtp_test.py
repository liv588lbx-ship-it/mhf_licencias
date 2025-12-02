# smtp_test.py
import smtplib, ssl

smtp_host = "smtp.gmail.com"
smtp_port = 587
user = "liv588lbx@gmail.com"
password = "jetw kpsm liwp nxtb"
from_addr = "liv588lbx@gmail.com"
to_addr = "shamanes@gmail.com"
msg = "Subject: Prueba SMTP\n\nPrueba de SMTP desde local."

context = ssl.create_default_context()
try:
    server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
    server.ehlo()
    server.starttls(context=context)
    server.ehlo()
    server.login(user, password)
    server.sendmail(from_addr, [to_addr], msg)
    server.quit()
    print("OK: email enviado (prueba).")
except Exception as e:
    print("ERROR SMTP:", type(e).__name__, str(e))
