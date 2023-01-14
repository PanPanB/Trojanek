import smtplib
import time
import win32com.client

smtp_server = 'smtp.example.com'
smtp_port = 587
smtp_acct = 'malwina1@poczta.int.pl'
smtp_password = 'seKret'
tgt_accts = ['malwina1@poczta.int.pl']

def plain_email(subject, contents):
    message = f'Subject: {subject}\nFrom {smtp_acct}\n'
    message += f'To: {tgt_accts}\n\n{contents.decode()}'
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_acct, smtp_password)

    server.sendmail(smtp_acct, tgt_accts, message)
    time.sleep(1)
    server.quit()

#to samo co powyzej tylko dla windy
def outlook(subject, contents):
    outlook = win32com.client.Dispatch("Outlook.Application")
    message = outlook.CreateItem(0)
    message.DeleteAfterSubmit = True
    message.Subject = subject
    message.Body = contents.decode()
    message.To = 'malwina1@poczta.int.pl'
    message.Send()


if __name__ == '__main__':
    plain_email('Wiadomosc testowa', 'Atak o swicie')
