#!/usr/bin/env python3

# Copyright (C) 2017-2019 sunborn23@github.com
# Copyright (C) 2019 CDMIUB@github.com

import configparser
import datetime
import email
import email.header
import email.mime.text
import imaplib
import os
import re
import smtplib
import sys
from _socket import gaierror

config = None
config_file_path = "autoresponder.config.ini"
config_file_path = "autoresponder.config.dev"
incoming_mail_server = None
outgoing_mail_server = None
statistics = {
    "start_time": datetime.datetime.now(),
    "mails_loading_error": 0,
    "mails_total": 0,
    "mails_processed": 0,
    "mails_in_trash": 0,
    "mails_wrong_sender": 0
}


def run():
    get_config_file_path()
    initialize_configuration()
    connect_to_mail_servers()
    check_folder_names()
    check_local_path()
    mails = fetch_emails()
    for mail in mails:
        process_email(mail)
    log_statistics()
    shutdown(0)


def get_config_file_path():
    if "--help" in sys.argv or "-h" in sys.argv:
        display_help_text()
    if "--config-path" in sys.argv and len(sys.argv) >= 3:
        global config_file_path
        config_file_path = sys.argv[2]
    if not os.path.isfile(config_file_path):
        shutdown_with_error("Configuration file not found. Expected it at '" + config_file_path + "'.")


def initialize_configuration():
    try:
        config_file = configparser.ConfigParser()
        config_file.read(config_file_path, encoding="UTF-8")
        global config
        config = {
            'in.user': cast(config_file["login credentials"]["mailserver.incoming.username"], str),
            'in.pw': cast(config_file["login credentials"]["mailserver.incoming.password"], str),
            'out.user': cast(config_file["login credentials"]["mailserver.outgoing.username"], str),
            'out.pw': cast(config_file["login credentials"]["mailserver.outgoing.password"], str),
            'display.name': cast(config_file["login credentials"]["mailserver.outgoing.display.name"], str),
            'display.mail': cast(config_file["login credentials"]["mailserver.outgoing.display.mail"], str),
            'in.host': cast(config_file["mail server settings"]["mailserver.incoming.imap.host"], str),
            'in.port': cast(config_file["mail server settings"]["mailserver.incoming.imap.port.ssl"], str),
            'out.host': cast(config_file["mail server settings"]["mailserver.outgoing.smtp.host"], str),
            'out.port': cast(config_file["mail server settings"]["mailserver.outgoing.smtp.port.tls"], str),
            'folders.inbox': cast(config_file["mail server settings"]["mailserver.incoming.folders.inbox.name"], str),
            'folders.trash': cast(config_file["mail server settings"]["mailserver.incoming.folders.trash.name"], str),
            'request.from': cast(config_file["mail content settings"]["mail.request.from"], str),
            'reply.subject': cast(config_file["mail content settings"]["mail.reply.subject"], str).strip(),
            'reply.body': cast(config_file["mail content settings"]["mail.reply.body"], str).strip(),
        }
    except KeyError as e:
        shutdown_with_error("Configuration file is invalid! (Key not found: " + str(e) + ")")
    depends = {
        'nothing': None,
        'delete': None,
        'forward': 'post.address',
        'move': 'post.folder',
        'download': 'post.path',
    }
    try:
        config['post.action'] = cast(config_file["post-reply action settings"]["post.action"], str).strip()
        if config['post.action'] not in depends:
          shutdown_with_error("Post-reply action {} is invalid!".format(config['post.action']))
    except KeyError:
        config['post.action'] = 'nothing'
        
    dkey=depends[config['post.action']]
    if dkey is not None:
      try:
          config[dkey]= cast(config_file["post-reply action settings"][dkey], str).strip()
      except KeyError as e:
          shutdown_with_error("Configuration file is invalid! (post.action = "+config['post.action']+" reqires "+dkey)


def connect_to_mail_servers():
    connect_to_imap()
    connect_to_smtp()


def check_folder_names():
    global incoming_mail_server
    global outgoing_mail_server
    (retcode, msg_count) = incoming_mail_server.select(config['folders.inbox'])
    if retcode != "OK" or re.match('[^0-9]',msg_count[0].decode()):
        shutdown_with_error("Inbox folder does not exist: " + config['folders.inbox'])
    (retcode, msg_count) = incoming_mail_server.select(config['folders.trash'])
    if retcode != "OK" or re.match('[^0-9]',msg_count[0].decode()):
        shutdown_with_error("Trash folder does not exist: " + config['folders.trash'])
    if 'post.folder' not in config:    
      return()
    (retcode, msg_count) = incoming_mail_server.select(config['post.folder'])
    if retcode != "OK" or re.match('[^0-9]',msg_count[0].decode()):
        shutdown_with_error("Destination folder does not exist: " + config['post.folder'])


def connect_to_imap():
    global incoming_mail_server
    try:
        do_connect_to_imap()
    except gaierror:
        shutdown_with_error("IMAP connection failed! Specified host not found.")
    except imaplib.IMAP4_SSL.error as e:
        shutdown_with_error("IMAP login failed! Reason: '" + cast(e.args[0], str, 'UTF-8') + "'.")
    except Exception as e:
        shutdown_with_error("IMAP connection/login failed! Reason: '" + cast(e, str) + "'.")


def do_connect_to_imap():
    global incoming_mail_server
    incoming_mail_server = imaplib.IMAP4_SSL(config['in.host'], config['in.port'])
    (retcode, capabilities) = incoming_mail_server.login(config['in.user'], config['in.pw'])
    if retcode != "OK":
        shutdown_with_error("IMAP login failed! Return code: '" + cast(retcode, str) + "'.")


def connect_to_smtp():
    global outgoing_mail_server
    try:
        do_connect_to_smtp()
    except gaierror:
        shutdown_with_error("SMTP connection failed! Specified host not found.")
    except smtplib.SMTPAuthenticationError as e:
        shutdown_with_error("SMTP login failed! Reason: '" + cast(e.smtp_error, str, 'UTF-8') + "'.")
    except Exception as e:
        shutdown_with_error("SMTP connection/login failed! Reason: '" + cast(e, str) + "'.")


def do_connect_to_smtp():
    global outgoing_mail_server
    outgoing_mail_server = smtplib.SMTP(config['out.host'], config['out.port'])
    outgoing_mail_server.starttls()
    (retcode, capabilities) = outgoing_mail_server.login(config['out.user'], config['out.pw'])
    if not (retcode == 235 or retcode == 250):
        shutdown_with_error("SMTP login failed! Return code: '" + str(retcode) + "'.")


def fetch_emails():
    global incoming_mail_server
    global outgoing_mail_server
    # get the message ids from the inbox folder
    incoming_mail_server.select(config['folders.inbox'])
    (retcode, message_indices) = incoming_mail_server.search(None, 'ALL')
    if retcode == 'OK':
        messages = []
        for message_index in message_indices[0].split():
            # get the actual message for the current index
            (retcode, data) = incoming_mail_server.fetch(message_index, '(RFC822)')
            if retcode == 'OK':
                # parse the message into a useful format
                message = email.message_from_string(data[0][1].decode('utf-8'))
                (retcode, data) = incoming_mail_server.fetch(message_index, "(UID)")
                if retcode == 'OK':
                    mail_uid = parse_uid(cast(data[0], str, 'UTF-8'))
                    message['mailserver_email_uid'] = mail_uid
                    messages.append(message)
                else:
                    statistics['mails_loading_error'] += 1
                    log_warning("Failed to get UID for email with index '" + message_index + "'.")
            else:
                statistics['mails_loading_error'] += 1
                log_warning("Failed to get email with index '" + message_index + "'.")
        statistics['mails_total'] = len(messages)
        return messages
    else:
        return []


def process_email(mail):
    try:
        mail_from = email.header.decode_header(mail['From'])
        mail_sender = mail_from[-1]
        mail_sender = cast(mail_sender[0], str, 'UTF-8')
        if config['request.from'] in mail_sender or config['request.from'] == '':
            reply_to_email(mail)
            if config['post.action'] == 'delete':
              delete_email(mail)
            elif config['post.action'] == 'forward':
              forward_email(mail)
            elif config['post.action'] == 'move':
              move_email(mail)
            elif config['post.action'] == 'download':
              download_email(mail)
            else:
              pass
        else:
            statistics['mails_wrong_sender'] += 1
        statistics['mails_processed'] += 1
    except Exception as e:
        log_warning("Unexpected error while processing email: '" + str(e) + "'.")


def reply_to_email(mail):
    global outgoing_mail_server
    try:
        receiver_emails = email.header.decode_header(mail['Reply-To'])
    except TypeError:
        receiver_emails = email.header.decode_header(mail['From'])
    #get actual email adress, in case field entry is in form "John Doe <john@example.com>"    
    for x,e in receiver_emails:
      e = 'utf-8' if e is None else e
      y = x.decode(e) if isinstance(x,bytes) else x
      if '@' in y:
        receiver_email = y
        break
    message = email.mime.text.MIMEText(config['reply.body'])
    message['Subject'] = config['reply.subject']
    message['To'] = receiver_email
    message['From'] = email.utils.formataddr((
        cast(email.header.Header(config['display.name'], 'utf-8'), str), config['display.mail']))
    outgoing_mail_server.sendmail(config['display.mail'], receiver_email, message.as_string())

def forward_email(mail):
    global outgoing_mail_server
    sender = email.header.decode_header(mail['From'])
    parts = []
    for x,e in sender :
      e = 'utf-8' if e is None else e
      y = x.decode(e) if isinstance(x,bytes) else x
      parts.append(y)
    prefix = '''
    
Forwarded email from {}
------------------------------------------------------------------  

    '''.format(' '.join(parts))  
    message = email.mime.text.MIMEText(prefix + mail.as_string())
    receiver_email = config['post.address']
    message['Subject'] = 'Fwd: {}'.format(mail['Subject'])
    message['To'] = receiver_email
    message['From'] = email.utils.formataddr((
        cast(email.header.Header(config['display.name'], 'utf-8'), str), config['display.mail']))
    outgoing_mail_server.sendmail(config['display.mail'], receiver_email, message.as_string())
    delete_email(mail)

def move_email(mail):
    global incoming_mail_server
    mail_uid=mail['mailserver_email_uid']
    retcode,_ = incoming_mail_server.uid('COPY', mail_uid, config['post.folder'])
    if retcode != "OK":
        shutdown_with_error("Failed moving message to folder: " + config['post.folder'])
    else:
        delete_email(mail)

def check_local_path():
    if not 'post.path' in config:
        return()
    path = config['post.path']
    if not os.path.isdir(path):
        shutdown_with_error("Local directory does not exist: "+path)
    if not os.access(path, os.W_OK):
        shutdown_with_error("Cannot write to local directory: "+path)
        
def download_email(mail):
    subject = email.header.decode_header(mail['Subject'])
    parts = []
    for x,e in subject :
      e = 'utf-8' if e is None else e
      y = x.decode(e) if isinstance(x,bytes) else x
      parts.append(y)
    short='_'.join(parts[0:min(len(y),5)])
    mail_uid=mail['mailserver_email_uid']
    filename = '{}_{}.txt'.format(mail_uid,short)
    path=os.path.join(config['post.path'],filename)
    with open(path,'wb') as f:
      f.write(mail.as_string().encode('utf-8'))
    delete_email(mail)

def delete_email(mail):
    global incoming_mail_server
    result = incoming_mail_server.uid('COPY', mail['mailserver_email_uid'], config['folders.trash'])
    if result[0] == "OK":
        statistics['mails_in_trash'] += 1
    else:
        log_warning("Copying email to trash failed. Reason: " + str(result))
    incoming_mail_server.uid('STORE', mail['mailserver_email_uid'], '+FLAGS', '(\Deleted)')
    incoming_mail_server.expunge()


def parse_uid(data):
    pattern_uid = re.compile('\d+ \(UID (?P<uid>\d+)\)')
    match = pattern_uid.match(data)
    return match.group('uid')


def cast(obj, to_type, options=None):
    try:
        if options is None:
            return to_type(obj)
        else:
            return to_type(obj, options)
    except ValueError and TypeError:
        return obj


def shutdown_with_error(message):
    message = "Error! " + str(message)
    message += "\nCurrent configuration file path: '" + str(config_file_path) + "'."
    if config is not None:
        message += "\nCurrent configuration: " + str(config)
    print(message)
    shutdown(1)


def log_warning(message):
    print("Warning! " + message)


def log_statistics():
    run_time = datetime.datetime.now() - statistics['start_time']
    total_mails = statistics['mails_total']
    loading_errors = statistics['mails_loading_error']
    wrong_sender_count = statistics['mails_wrong_sender']
    processing_errors = total_mails - statistics['mails_processed']
    moving_errors = statistics['mails_processed'] - statistics['mails_in_trash'] - statistics['mails_wrong_sender']
    total_warnings = loading_errors + processing_errors + moving_errors
    message = "Executed "
    message += "without warnings " if total_warnings is 0 else "with " + str(total_warnings) + " warnings "
    message += "in " + str(run_time.total_seconds()) + " seconds. "
    message += "Found " + str(total_mails) + " emails in inbox"
    message += ". " if wrong_sender_count is 0 else " with " + str(wrong_sender_count) + " emails from wrong senders. "
    message += "Processed " + str(statistics['mails_processed']) + \
               " emails, replied to " + str(total_mails - wrong_sender_count) + " emails. "
    if total_warnings is not 0:
        message += "Encountered " + str(loading_errors) + " errors while loading emails, " + \
                   str(processing_errors) + " errors while processing emails and " + \
                   str(moving_errors) + " errors while moving emails to trash."
    print(message)


def display_help_text():
    print("Options:")
    print("\t--help: Display this help information")
    print("\t--config-path <path/to/config/file>: "
          "Override path to config file (defaults to same directory as the script is)")
    exit(0)


def shutdown(error_code):
    if incoming_mail_server is not None:
        try:
            incoming_mail_server.close()
        except Exception:
            pass
        try:
            incoming_mail_server.logout()
        except Exception:
            pass
    if outgoing_mail_server is not None:
        try:
            outgoing_mail_server.quit()
        except Exception:
            pass
    if error_code != 0:
      raise SystemExit


run()
