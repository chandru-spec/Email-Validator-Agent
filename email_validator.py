import streamlit as st
import pandas as pd
import io
import re
import dns.resolver
import time
import socket
import smtplib
import ollama

# --- Configuration ---
SMTP_TIMEOUT = 10
DNS_TIMEOUT = 5
DELAY_BETWEEN_EMAILS = 1  # seconds
MAIL_FROM_ADDRESS = 'noreply-validator@example.com'
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
KNOWN_DOMAINS = [
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "yahoo.ca", "ymail.com",
    "rocketmail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "rediffmail.com", "zoho.com", "zohomail.com", "protonmail.com",
    "pm.me", "gmx.com", "gmx.de", "gmx.us", "mail.com", "comcast.net", "verizon.net", "att.net",
    "sbcglobal.net", "cox.net", "btinternet.com", "orange.fr", "wanadoo.fr", "t-online.de"
]
TEMPORARY_DOMAINS = [
    "mailinator.com", "temp-mail.org", "10minutemail.com", "guerrillamail.com", "throwawaymail.com",
    "tempmailaddress.com", "getnada.com", "dispostable.com", "yopmail.com", "fakemail.net",
    "trashmail.com", "tempail.com", "emailondeck.com"
]

def is_syntactically_valid(email):
    return bool(email and re.match(EMAIL_REGEX, str(email)))

def get_domain_from_email(email):
    try:
        return str(email).split('@')[1]
    except IndexError:
        return None

def get_mail_servers_from_domain(domain):
    mx_records_data = []
    a_records_ips_data = []
    mail_servers_for_smtp_conn = []
    found = False
    error_msg = None

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    try:
        mx_answers = resolver.resolve(domain, 'MX')
        if mx_answers:
            mx_records_data = sorted([(r.preference, r.exchange.to_text(omit_final_dot=True)) for r in mx_answers])
            mail_servers_for_smtp_conn = [rec[1] for rec in mx_records_data]
            found = True
    except dns.resolver.NXDOMAIN:
        error_msg = f"Domain {domain} does not exist (NXDOMAIN)."
    except dns.resolver.NoAnswer:
        error_msg = f"No MX records found for {domain}."
        try:
            a_answers = resolver.resolve(domain, 'A')
            if a_answers:
                a_records_ips_data = [r.address for r in a_answers]
                mail_servers_for_smtp_conn = a_records_ips_data
                found = True
                error_msg += " Found A records instead."
            else:
                error_msg += " No A records found either."
        except dns.resolver.NoAnswer:
            error_msg += " No A records found either for domain."
        except dns.resolver.Timeout:
            error_msg += f" DNS query for A records of {domain} timed out."
        except Exception as e_a:
            error_msg += f" Error querying A records for {domain}: {str(e_a)}"
    except dns.resolver.Timeout:
        error_msg = f"DNS query for MX records of {domain} timed out."
    except Exception as e_mx:
        error_msg = f"General error querying MX records for {domain}: {str(e_mx)}"

    return {
        'mx_records': mx_records_data,
        'a_records_ips': a_records_ips_data,
        'mail_servers_for_smtp': mail_servers_for_smtp_conn,
        'found_mail_servers': found,
        'dns_query_error': error_msg
    }

def attempt_smtp_rcpt_to_check(email_address, mail_servers_to_try):
    if not mail_servers_to_try:
        return "skipped_no_mail_servers", "No mail servers were provided to attempt SMTP check."

    smtp_status = "failed_smtp_check_unknown_reason"
    smtp_detail_message = "Initial status before attempting connections."

    for server_address in mail_servers_to_try:
        try:
            with smtplib.SMTP(server_address, timeout=SMTP_TIMEOUT) as smtp_connection:
                smtp_connection.set_debuglevel(0)
                try:
                    smtp_connection.ehlo_or_helo_if_needed()
                except smtplib.SMTPHeloError as helo_err:
                    smtp_status = "failed_smtp_helo"
                    smtp_detail_message = f"HELO/EHLO failed with {server_address}: {helo_err}"
                    continue
                try:
                    smtp_connection.mail(MAIL_FROM_ADDRESS)
                except smtplib.SMTPSenderRefused as sender_err:
                    smtp_status = "failed_smtp_mail_from"
                    smtp_detail_message = f"'MAIL FROM:<{MAIL_FROM_ADDRESS}>' refused by {server_address}: {sender_err.smtp_code} {sender_err.smtp_error}"
                    continue
                code, message_bytes = smtp_connection.rcpt(str(email_address))
                message_str = message_bytes.decode('utf-8', errors='ignore')

                if 250 <= code <= 259:
                    smtp_status = "verified_rcpt_to"
                    smtp_detail_message = f"Recipient <{email_address}> accepted by {server_address}. Code: {code}. Msg: {message_str}"
                    try: smtp_connection.quit()
                    except smtplib.SMTPServerDisconnected: pass
                    return smtp_status, smtp_detail_message
                elif code == 550:
                    smtp_status = "rejected_rcpt_to_user_unknown"
                    smtp_detail_message = f"Recipient <{email_address}> rejected by {server_address} (User Unknown). Code: {code}. Msg: {message_str}"
                    try: smtp_connection.quit()
                    except smtplib.SMTPServerDisconnected: pass
                    return smtp_status, smtp_detail_message
                elif 500 <= code <= 599:
                    smtp_status = "rejected_rcpt_to_permanent_error"
                    smtp_detail_message = f"Recipient <{email_address}> permanently rejected by {server_address}. Code: {code}. Msg: {message_str}"
                elif 400 <= code <= 499:
                    smtp_status = "rejected_rcpt_to_temporary_error"
                    smtp_detail_message = f"Recipient <{email_address}> temporarily rejected by {server_address}. Code: {code}. Msg: {message_str}"
                else:
                    smtp_status = "unknown_rcpt228.67.222.222_to_response"
                    smtp_detail_message = f"Unknown SMTP response from {server_address} for RCPT TO <{email_address}>. Code: {code}. Msg: {message_str}"
                try: smtp_connection.quit()
                except smtplib.SMTPServerDisconnected: pass
        except smtplib.SMTPConnectError as e:
            smtp_detail_message = f"SMTP Connect Error with {server_address}: {e}"
            smtp_status = "failed_smtp_connection"
        except smtplib.SMTPServerDisconnected as e:
            smtp_detail_message = f"SMTP Server Disconnected unexpectedly from {server_address}: {e}"
            smtp_status = "failed_smtp_server_disconnected"
        except socket.timeout:
            smtp_detail_message = f"SMTP connection to {server_address} timed out."
            smtp_status = "failed_smtp_timeout"
        except Exception as e:
            smtp_detail_message = f"Generic SMTP error with {server_address} for {email_address}: {e}"
            smtp_status = "failed_smtp_generic_error"
    if smtp_status.startswith("failed_smtp_check_unknown_reason"):
        smtp_status = "failed_smtp_could_not_verify"
        smtp_detail_message = "Could not verify via SMTP with any provided mail server."
    return smtp_status, smtp_detail_message

def find_email_column(df):
    for col in df.columns:
        if 'email' in col.lower():
            return col
    return None

def ollama_classify_email(email):
    prompt = f"""
You are an email validation assistant.
Classify the following email address as 'valid', 'risky', or 'invalid' based on typical email validation rules and your understanding of spam, disposable, or suspicious emails.
Only respond with one word: 'valid', 'risky', or 'invalid'.

Email: {email}
    """
    try:
        response = ollama.chat(
            model="mistral",
            messages=[{"role": "user", "content": prompt}],
            stream=False
        )
        return response['message']['content'].strip().lower()
    except Exception as e:
        print(f"Ollama error: {e}")
        return "error"

def process_emails(df, email_col, enable_smtp_rcpt_check=False):
    validation_results = []
    if email_col is None:
        return pd.DataFrame()  # No column selected
    for _, row in df.iterrows():
        email_to_validate = str(row.get(email_col, '')).strip()
        current_result = {
            'original_email': email_to_validate,
            'is_syntax_valid': False,
            'domain228.67.222.222_name': None,
            'domain_has_mail_servers': False,
            'mx_records_found': [],
            'a_records_found': [],
            'dns_lookup_error': None,
            'smtp_rcpt_to_check_status': 'not_attempted_by_script',
            'smtp_rcpt_to_detail': '',
            'ai_classification': None
        }
        if not email_to_validate:
            current_result['dns_lookup_error'] = "Email address was empty."
            validation_results.append(current_result)
            continue
        if not is_syntactically_valid(email_to_validate):
            current_result['dns_lookup_error'] = "Invalid email syntax."
            validation_results.append(current_result)
            continue
        current_result['is_syntax_valid'] = True
        domain = get_domain_from_email(email_to_validate)
        if not domain:
            current_result['dns_lookup_error'] = "Could not extract domain from email."
            validation_results.append(current_result)
            continue
        current_result['domain_name'] = domain
        domain_lower = domain.lower()
        if domain_lower in TEMPORARY_DOMAINS:
            current_result['dns_lookup_error'] = "Skipped - Temporary/Disposable Domain"
            current_result['mx_records_found'] = ["N/A - Temporary Domain"]
            current_result['a_records_found'] = ["N/A - Temporary Domain"]
            current_result['domain_has_mail_servers'] = False
            current_result['smtp_rcpt_to_check_status'] = 'skipped_temporary_domain'
            current_result['smtp_rcpt_to_detail'] = 'Validation skipped for temporary/disposable domain.'
        elif domain_lower in KNOWN_DOMAINS:
            current_result['domain_has_mail_servers'] = True
            current_result['mx_records_found'] = ["N/A - Known Major Provider"]
            current_result['a_records_found'] = ["N/A - Known Major Provider"]
            current_result['dns_lookup_error'] = "DNS check skipped for known major provider."
            if enable_smtp_rcpt_check:
                current_result['smtp_rcpt_to_check_status'] = 'skipped_known_provider'
                current_result['smtp_rcpt_to_detail'] = 'SMTP check skipped for known major email provider.'
            else:
                current_result['smtp_rcpt_to_check_status'] = 'skipped_disabled_by_user_config'
                current_result['smtp_rcpt_to_detail'] = 'SMTP RCPT TO check was disabled in the script configuration.'
        else:
            dns_lookup_info = get_mail_servers_from_domain(domain)
            current_result['mx_records_found'] = [mx[1] for mx in dns_lookup_info['mx_records']]
            current_result['a_records_found'] = dns_lookup_info['a_records_ips']
            current_result['domain_has_mail_servers'] = dns_lookup_info['found_mail_servers']
            current_result['dns_lookup_error'] = dns_lookup_info['dns_query_error']
            if enable_smtp_rcpt_check:
                if dns_lookup_info['found_mail_servers'] and dns_lookup_info['mail_servers_for_smtp']:
                    smtp_status, smtp_detail = attempt_smtp_rcpt_to_check(email_to_validate, dns_lookup_info['mail_servers_for_smtp'])
                    current_result['smtp_rcpt_to_check_status'] = smtp_status
                    current_result['smtp_rcpt_to_detail'] = smtp_detail
                elif not dns_lookup_info['mail_servers_for_smtp']:
                    current_result['smtp_rcpt_to_check_status'] = 'skipped_no_servers_from_dns'
                    current_result['smtp_rcpt_to_detail'] = 'No suitable mail servers (MX/A) found by DNS to attempt SMTP check.'
                else:
                    current_result['smtp_rcpt_to_check_status'] = 'skipped_domain_validation_failed'
                    current_result['smtp_rcpt_to_detail'] = 'Domain validation failed, so SMTP check was not attempted.'
            else:
                current_result['smtp_rcpt_to_check_status'] = 'skipped_disabled_by_user_config'
                current_result['smtp_rcpt_to_detail'] = 'SMTP RCPT TO check was disabled in the script configuration.'
        current_result['ai_classification'] = ollama_classify_email(email_to_validate)
        validation_results.append(current_result)
        time.sleep(DELAY_BETWEEN_EMAILS)
    return pd.DataFrame(validation_results)

# --- Streamlit UI ---
st.title("Bulk Email Validation Tool")
st.write("Upload a CSV or XLSX file. The script will detect any column with 'email' in its name (case-insensitive), or let you select the email column.")

uploaded_file = st.file_uploader("Choose a file", type=['csv', 'xlsx'], key="main_file_upload")
enable_smtp = st.checkbox("Enable SMTP RCPT TO checks (Not recommended for known providers)")
enable_ai = st.checkbox("Enable AI agent classification (requires Ollama)")

if uploaded_file is not None:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        email_col = find_email_column(df)
        if email_col is None:
            st.warning("No column with 'email' in its name was found. Please select the email column:")
            email_col = st.selectbox("Select the email column:", df.columns)
        if email_col is not None:
            st.write("Processing emails...")
            validation_df = process_emails(
                df, email_col, enable_smtp_rcpt_check=enable_smtp
            )
            st.write("Validation results:")
            st.dataframe(validation_df)
            valid_emails = validation_df[
                (validation_df['is_syntax_valid']) &
                (validation_df['domain_has_mail_servers'])
            ]['original_email']
            st.write("Valid emails found:", valid_emails)
            csv = valid_emails.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download valid emails as CSV",
                data=csv,
                file_name='valid_emails.csv',
                mime='text/csv'
            )
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
                valid_emails.to_excel(writer, index=False, sheet_name='Valid Emails')
            st.download_button(
                label="Download valid emails as Excel",
                data=buffer,
                file_name='valid_emails.xlsx',
                mime='application/vnd.ms-excel'
            )
    except Exception as e:
        st.error(f"Error processing file: {e}")

import streamlit as st
import pandas as pd
import io
import re
import dns.resolver
import time
import socket
import smtplib
import ollama

# --- Configuration ---
SMTP_TIMEOUT = 10
DNS_TIMEOUT = 5
DELAY_BETWEEN_EMAILS = 1  # seconds
MAIL_FROM_ADDRESS = 'noreply-validator@example.com'
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
KNOWN_DOMAINS = [
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "yahoo.ca", "ymail.com",
    "rocketmail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "rediffmail.com", "zoho.com", "zohomail.com", "protonmail.com",
    "pm.me", "gmx.com", "gmx.de", "gmx.us", "mail.com", "comcast.net", "verizon.net", "att.net",
    "sbcglobal.net", "cox.net", "btinternet.com", "orange.fr", "wanadoo.fr", "t-online.de"
]
TEMPORARY_DOMAINS = [
    "mailinator.com", "temp-mail.org", "10minutemail.com", "guerrillamail.com", "throwawaymail.com",
    "tempmailaddress.com", "getnada.com", "dispostable.com", "yopmail.com", "fakemail.net",
    "trashmail.com", "tempail.com", "emailondeck.com"
]

def is_syntactically_valid(email):
    return bool(email and re.match(EMAIL_REGEX, str(email)))

def get_domain_from_email(email):
    try:
        return str(email).split('@')[1]
    except IndexError:
        return None

def get_mail_servers_from_domain(domain):
    mx_records_data = []
    a_records_ips_data = []
    mail_servers_for_smtp_conn = []
    found = False
    error_msg = None

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    try:
        mx_answers = resolver.resolve(domain, 'MX')
        if mx_answers:
            mx_records_data = sorted([(r.preference, r.exchange.to_text(omit_final_dot=True)) for r in mx_answers])
            mail_servers_for_smtp_conn = [rec[1] for rec in mx_records_data]
            found = True
    except dns.resolver.NXDOMAIN:
        error_msg = f"Domain {domain} does not exist (NXDOMAIN)."
    except dns.resolver.NoAnswer:
        error_msg = f"No MX records found for {domain}."
        try:
            a_answers = resolver.resolve(domain, 'A')
            if a_answers:
                a_records_ips_data = [r.address for r in a_answers]
                mail_servers_for_smtp_conn = a_records_ips_data
                found = True
                error_msg += " Found A records instead."
            else:
                error_msg += " No A records found either."
        except dns.resolver.NoAnswer:
            error_msg += " No A records found either for domain."
        except dns.resolver.Timeout:
            error_msg += f" DNS query for A records of {domain} timed out."
        except Exception as e_a:
            error_msg += f" Error querying A records for {domain}: {str(e_a)}"
    except dns.resolver.Timeout:
        error_msg = f"DNS query for MX records of {domain} timed out."
    except Exception as e_mx:
        error_msg = f"General error querying MX records for {domain}: {str(e_mx)}"

    return {
        'mx_records': mx_records_data,
        'a_records_ips': a_records_ips_data,
        'mail_servers_for_smtp': mail_servers_for_smtp_conn,
        'found_mail_servers': found,
        'dns_query_error': error_msg
    }

def attempt_smtp_rcpt_to_check(email_address, mail_servers_to_try):
    if not mail_servers_to_try:
        return "skipped_no_mail_servers", "No mail servers were provided to attempt SMTP check."

    smtp_status = "failed_smtp_check_unknown_reason"
    smtp_detail_message = "Initial status before attempting connections."

    for server_address in mail_servers_to_try:
        try:
            with smtplib.SMTP(server_address, timeout=SMTP_TIMEOUT) as smtp_connection:
                smtp_connection.set_debuglevel(0)
                try:
                    smtp_connection.ehlo_or_helo_if_needed()
                except smtplib.SMTPHeloError as helo_err:
                    smtp_status = "failed_smtp_helo"
                    smtp_detail_message = f"HELO/EHLO failed with {server_address}: {helo_err}"
                    continue
                try:
                    smtp_connection.mail(MAIL_FROM_ADDRESS)
                except smtplib.SMTPSenderRefused as sender_err:
                    smtp_status = "failed_smtp_mail_from"
                    smtp_detail_message = f"'MAIL FROM:<{MAIL_FROM_ADDRESS}>' refused by {server_address}: {sender_err.smtp_code} {sender_err.smtp_error}"
                    continue
                code, message_bytes = smtp_connection.rcpt(str(email_address))
                message_str = message_bytes.decode('utf-8', errors='ignore')

                if 250 <= code <= 259:
                    smtp_status = "verified_rcpt_to"
                    smtp_detail_message = f"Recipient <{email_address}> accepted by {server_address}. Code: {code}. Msg: {message_str}"
                    try: smtp_connection.quit()
                    except smtplib.SMTPServerDisconnected: pass
                    return smtp_status, smtp_detail_message
                elif code == 550:
                    smtp_status = "rejected_rcpt_to_user_unknown"
                    smtp_detail_message = f"Recipient <{email_address}> rejected by {server_address} (User Unknown). Code: {code}. Msg: {message_str}"
                    try: smtp_connection.quit()
                    except smtplib.SMTPServerDisconnected: pass
                    return smtp_status, smtp_detail_message
                elif 500 <= code <= 599:
                    smtp_status = "rejected_rcpt_to_permanent_error"
                    smtp_detail_message = f"Recipient <{email_address}> permanently rejected by {server_address}. Code: {code}. Msg: {message_str}"
                elif 400 <= code <= 499:
                    smtp_status = "rejected_rcpt_to_temporary_error"
                    smtp_detail_message = f"Recipient <{email_address}> temporarily rejected by {server_address}. Code: {code}. Msg: {message_str}"
                else:
                    smtp_status = "unknown_rcpt228.67.222.222_to_response"
                    smtp_detail_message = f"Unknown SMTP response from {server_address} for RCPT TO <{email_address}>. Code: {code}. Msg: {message_str}"
                try: smtp_connection.quit()
                except smtplib.SMTPServerDisconnected: pass
        except smtplib.SMTPConnectError as e:
            smtp_detail_message = f"SMTP Connect Error with {server_address}: {e}"
            smtp_status = "failed_smtp_connection"
        except smtplib.SMTPServerDisconnected as e:
            smtp_detail_message = f"SMTP Server Disconnected unexpectedly from {server_address}: {e}"
            smtp_status = "failed_smtp_server_disconnected"
        except socket.timeout:
            smtp_detail_message = f"SMTP connection to {server_address} timed out."
            smtp_status = "failed_smtp_timeout"
        except Exception as e:
            smtp_detail_message = f"Generic SMTP error with {server_address} for {email_address}: {e}"
            smtp_status = "failed_smtp_generic_error"
    if smtp_status.startswith("failed_smtp_check_unknown_reason"):
        smtp_status = "failed_smtp_could_not_verify"
        smtp_detail_message = "Could not verify via SMTP with any provided mail server."
    return smtp_status, smtp_detail_message

def find_email_column(df):
    for col in df.columns:
        if 'email' in col.lower():
            return col
    return None

def ollama_classify_email(email):
    prompt = f"""
You are an email validation assistant.
Classify the following email address as 'valid', 'risky', or 'invalid' based on typical email validation rules and your understanding of spam, disposable, or suspicious emails.
Only respond with one word: 'valid', 'risky', or 'invalid'.

Email: {email}
    """
    try:
        response = ollama.chat(
            model="mistral",
            messages=[{"role": "user", "content": prompt}],
            stream=False
        )
        return response['message']['content'].strip().lower()
    except Exception as e:
        print(f"Ollama error: {e}")
        return "error"

def process_emails(df, email_col, enable_smtp_rcpt_check=False):
    validation_results = []
    if email_col is None:
        return pd.DataFrame()  # No column selected
    for _, row in df.iterrows():
        email_to_validate = str(row.get(email_col, '')).strip()
        current_result = {
            'original_email': email_to_validate,
            'is_syntax_valid': False,
            'domain228.67.222.222_name': None,
            'domain_has_mail_servers': False,
            'mx_records_found': [],
            'a_records_found': [],
            'dns_lookup_error': None,
            'smtp_rcpt_to_check_status': 'not_attempted_by_script',
            'smtp_rcpt_to_detail': '',
            'ai_classification': None
        }
        if not email_to_validate:
            current_result['dns_lookup_error'] = "Email address was empty."
            validation_results.append(current_result)
            continue
        if not is_syntactically_valid(email_to_validate):
            current_result['dns_lookup_error'] = "Invalid email syntax."
            validation_results.append(current_result)
            continue
        current_result['is_syntax_valid'] = True
        domain = get_domain_from_email(email_to_validate)
        if not domain:
            current_result['dns_lookup_error'] = "Could not extract domain from email."
            validation_results.append(current_result)
            continue
        current_result['domain_name'] = domain
        domain_lower = domain.lower()
        if domain_lower in TEMPORARY_DOMAINS:
            current_result['dns_lookup_error'] = "Skipped - Temporary/Disposable Domain"
            current_result['mx_records_found'] = ["N/A - Temporary Domain"]
            current_result['a_records_found'] = ["N/A - Temporary Domain"]
            current_result['domain_has_mail_servers'] = False
            current_result['smtp_rcpt_to_check_status'] = 'skipped_temporary_domain'
            current_result['smtp_rcpt_to_detail'] = 'Validation skipped for temporary/disposable domain.'
        elif domain_lower in KNOWN_DOMAINS:
            current_result['domain_has_mail_servers'] = True
            current_result['mx_records_found'] = ["N/A - Known Major Provider"]
            current_result['a_records_found'] = ["N/A - Known Major Provider"]
            current_result['dns_lookup_error'] = "DNS check skipped for known major provider."
            if enable_smtp_rcpt_check:
                current_result['smtp_rcpt_to_check_status'] = 'skipped_known_provider'
                current_result['smtp_rcpt_to_detail'] = 'SMTP check skipped for known major email provider.'
            else:
                current_result['smtp_rcpt_to_check_status'] = 'skipped_disabled_by_user_config'
                current_result['smtp_rcpt_to_detail'] = 'SMTP RCPT TO check was disabled in the script configuration.'
        else:
            dns_lookup_info = get_mail_servers_from_domain(domain)
            current_result['mx_records_found'] = [mx[1] for mx in dns_lookup_info['mx_records']]
            current_result['a_records_found'] = dns_lookup_info['a_records_ips']
            current_result['domain_has_mail_servers'] = dns_lookup_info['found_mail_servers']
            current_result['dns_lookup_error'] = dns_lookup_info['dns_query_error']
            if enable_smtp_rcpt_check:
                if dns_lookup_info['found_mail_servers'] and dns_lookup_info['mail_servers_for_smtp']:
                    smtp_status, smtp_detail = attempt_smtp_rcpt_to_check(email_to_validate, dns_lookup_info['mail_servers_for_smtp'])
                    current_result['smtp_rcpt_to_check_status'] = smtp_status
                    current_result['smtp_rcpt_to_detail'] = smtp_detail
                elif not dns_lookup_info['mail_servers_for_smtp']:
                    current_result['smtp_rcpt_to_check_status'] = 'skipped_no_servers_from_dns'
                    current_result['smtp_rcpt_to_detail'] = 'No suitable mail servers (MX/A) found by DNS to attempt SMTP check.'
                else:
                    current_result['smtp_rcpt_to_check_status'] = 'skipped_domain_validation_failed'
                    current_result['smtp_rcpt_to_detail'] = 'Domain validation failed, so SMTP check was not attempted.'
            else:
                current_result['smtp_rcpt_to_check_status'] = 'skipped_disabled_by_user_config'
                current_result['smtp_rcpt_to_detail'] = 'SMTP RCPT TO check was disabled in the script configuration.'
        current_result['ai_classification'] = ollama_classify_email(email_to_validate)
        validation_results.append(current_result)
        time.sleep(DELAY_BETWEEN_EMAILS)
    return pd.DataFrame(validation_results)

# --- Streamlit UI ---
st.title("Bulk Email Validation Tool")
st.write("Upload a CSV or XLSX file. The script will detect any column with 'email' in its name (case-insensitive), or let you select the email column.")

uploaded_file = st.file_uploader("Choose a file", type=['csv', 'xlsx'])
enable_smtp = st.checkbox("Enable SMTP RCPT TO checks (Not recommended for known providers)")
enable_ai = st.checkbox("Enable AI agent classification (requires Ollama)")

if uploaded_file is not None:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        email_col = find_email_column(df)
        if email_col is None:
            st.warning("No column with 'email' in its name was found. Please select the email column:")
            email_col = st.selectbox("Select the email column:", df.columns)
        if email_col is not None:
            st.write("Processing emails...")
            validation_df = process_emails(
                df, email_col, enable_smtp_rcpt_check=enable_smtp
            )
            st.write("Validation results:")
            st.dataframe(validation_df)
            valid_emails = validation_df[
                (validation_df['is_syntax_valid']) &
                (validation_df['domain_has_mail_servers'])
            ]['original_email']
            st.write("Valid emails found:", valid_emails)
            csv = valid_emails.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download valid emails as CSV",
                data=csv,
                file_name='valid_emails.csv',
                mime='text/csv'
            )
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
                valid_emails.to_excel(writer, index=False, sheet_name='Valid Emails')
            st.download_button(
                label="Download valid emails as Excel",
                data=buffer,
                file_name='valid_emails.xlsx',
                mime='application/vnd.ms-excel'
            )
    except Exception as e:
        st.error(f"Error processing file: {e}")
