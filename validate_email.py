# RFC 2822 - style email validation for Python
# (c) 2012 Syrus Akbary <me@syrusakbary.com>
# Extended from (c) 2011 Noel Bush <noel@aitools.org>
# for support of mx and user check
# This code is made available to you under the GNU LGPL v3.
#
# This module provides a single method, valid_email_address(),
# which returns True or False to indicate whether a given address
# is valid according to the 'addr-spec' part of the specification
# given in RFC 2822.  Ideally, we would like to find this
# in some other library, already thoroughly tested and well-
# maintained.  The standard Python library email.utils
# contains a parse_addr() function, but it is not sufficient
# to detect many malformed addresses.
#
# This implementation aims to be faithful to the RFC, with the
# exception of a circular definition (see comments below), and
# with the omission of the pattern components marked as "obsolete".

import logging
import re
import smtplib
import socket

from disposable_email_domains import blocklist

# All we are really doing is comparing the input string to one
# gigantic regular expression.  But building that regexp, and
# ensuring its correctness, is made much easier by assembling it
# from the "tokens" defined by the RFC.  Each of these tokens is
# tested in the accompanying unit test file.
#
# The section of RFC 2822 from which each pattern component is
# derived is given in an accompanying comment.
#
# (To make things simple, every string below is given as 'raw',
# even when it's not strictly necessary.  This way we don't forget
# when it is necessary.)
#
WSP = r'[\s]'  # see 2.2.2. Structured Header Field Bodies
CRLF = r'(?:\r\n)'  # see 2.2.3. Long Header Fields
NO_WS_CTL = r'\x01-\x08\x0b\x0c\x0f-\x1f\x7f'  # see 3.2.1. Primitive Tokens
QUOTED_PAIR = r'(?:\\.)'  # see 3.2.2. Quoted characters
FWS = r'(?:(?:' + WSP + r'*' + CRLF + r')?' + WSP + r'+)'  # see 3.2.3. Folding white space and comments
CTEXT = r'[' + NO_WS_CTL + r'\x21-\x27\x2a-\x5b\x5d-\x7e]'  # see 3.2.3
# (NB: The RFC includes COMMENT here as well, but that would be circular.)
CCONTENT = r'(?:' + CTEXT + r'|' + QUOTED_PAIR + r')'  # see 3.2.3
COMMENT = r'\((?:' + FWS + r'?' + CCONTENT + r')*' + FWS + r'?\)'  # see 3.2.3
CFWS = r'(?:' + FWS + r'?' + COMMENT + ')*(?:' + FWS + '?' + COMMENT + '|' + FWS + ')'  # see 3.2.3
ATEXT = r'[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]'  # see 3.2.4. Atom
ATOM = CFWS + r'?' + ATEXT + r'+' + CFWS + r'?'  # see 3.2.4
DOT_ATOM_TEXT = ATEXT + r'+(?:\.' + ATEXT + r'+)*'  # see 3.2.4
DOT_ATOM = CFWS + r'?' + DOT_ATOM_TEXT + CFWS + r'?'  # see 3.2.4
QTEXT = r'[' + NO_WS_CTL + r'\x21\x23-\x5b\x5d-\x7e]'  # see 3.2.5. Quoted strings
QCONTENT = r'(?:' + QTEXT + r'|' + QUOTED_PAIR + r')'  # see 3.2.5
QUOTED_STRING = CFWS + r'?' + r'"(?:' + FWS + r'?' + QCONTENT + r')*' + FWS + r'?' + r'"' + CFWS + r'?'
LOCAL_PART = r'(?:' + DOT_ATOM + r'|' + QUOTED_STRING + r')'  # see 3.4.1. Addr-spec specification
DTEXT = r'[' + NO_WS_CTL + r'\x21-\x5a\x5e-\x7e]'  # see 3.4.1
DCONTENT = r'(?:' + DTEXT + r'|' + QUOTED_PAIR + r')'  # see 3.4.1
DOMAIN_LITERAL = CFWS + r'?' + r'\[' + r'(?:' + FWS + r'?' + DCONTENT + r')*' + FWS + r'?\]' + CFWS + r'?'  # see 3.4.1
DOMAIN = r'(?:' + DOT_ATOM + r'|' + DOMAIN_LITERAL + r')'  # see 3.4.1
ADDR_SPEC = LOCAL_PART + r'@' + DOMAIN  # see 3.4.1
VALID_ADDRESS_REGEXP = '^' + ADDR_SPEC + '$'  # A valid address will match exactly the 3.4.1 addr-spec.
MX_DNS_CACHE = {}
MX_CHECK_CACHE = {}

logger = logging.getLogger(__name__)


def is_disposable(email, debug=False):
    """Indicate whether the email is known as being a disposable email or not"""
    email_domain = email.rsplit('@', 1)[1]
    if email_domain in blocklist:
        if debug:
            logger.warning("Email %s is flagged as disposable (domain=%s)", email, email_domain)
        return True
    return False


def get_mx_ip(hostname):
    from dns import resolver, exception

    if hostname not in MX_DNS_CACHE:
        try:
            answers = resolver.query(hostname, 'MX')
            MX_DNS_CACHE[hostname] = answers

        except exception.Timeout as e:
            return False

        except exception.DNSException as e:
            if isinstance(e, resolver.NXDOMAIN):  # or e.rcode == 2:  # SERVFAIL
                MX_DNS_CACHE[hostname] = None
            else:
                raise e

    return MX_DNS_CACHE[hostname]


def validate_email(email,
                   check_mx=False,
                   verify=False,
                   debug=False,
                   smtp_timeout=10,
                   allow_disposable=True,
                   sending_email='',
                   ):
    """Indicate whether the given string is a valid email address
    according to the 'addr-spec' portion of RFC 2822 (see section
    3.4.1).  Parts of the spec that are marked obsolete are *not*
    included in this test, and certain arcane constructions that
    depend on circular definitions in the spec may not pass, but in
    general this should correctly identify any email address likely
    to be in use as of 2011."""
    if debug:
        logger.setLevel(logging.DEBUG)

    try:
        assert re.match(VALID_ADDRESS_REGEXP, email) is not None
        if not allow_disposable and is_disposable(email, debug=debug):
            return False

        check_mx |= verify
        if check_mx:
            hostname = email[email.find('@') + 1:]
            mx_hosts = get_mx_ip(hostname)
            if mx_hosts is None:
                return False
            elif mx_hosts is False:
                return None
            for mx in mx_hosts:
                exchange = mx.exchange.to_text(omit_final_dot=True)
                try:
                    if not verify and exchange in MX_CHECK_CACHE:
                        return MX_CHECK_CACHE[exchange]
                    smtp = smtplib.SMTP(timeout=smtp_timeout)
                    smtp.connect(exchange)
                    MX_CHECK_CACHE[exchange] = True
                    if not verify:
                        try:
                            smtp.quit()
                        except smtplib.SMTPServerDisconnected:
                            pass
                        return True
                    status, _ = smtp.helo()
                    if status != 250:
                        smtp.quit()
                        if debug:
                            logger.debug(u'%s answer: %s - %s', exchange, status, _)
                        continue
                    smtp.mail(sending_email)
                    status, _ = smtp.rcpt(email)
                    if status == 250:
                        smtp.quit()
                        return True
                    elif status == 550:
                        if 'unknown' in _ and '5.1.1' in _:  # postfix error for unvalid email
                            return False
                    if debug:
                        logger.debug(u'%s answer: %s - %s', exchange, status, _)
                    smtp.quit()
                except smtplib.SMTPServerDisconnected:  # Server not permits verify user
                    if debug:
                        logger.debug(u'%s disconected.', exchange)
                        raise
                except smtplib.SMTPConnectError:
                    if debug:
                        logger.debug(u'Unable to connect to %s.', exchange)
            return None

    except socket.error as e:
        if debug:
            logger.debug('ServerError or socket.error exception raised (%s).', e)
        return None

    except Exception as e:
        if debug:
            logger.debug('Unknown exception raised (%s).', e)
        return False

    return True


def interactive_check():
    import time
    try:
        from builtins import input
    except ImportError:
        from builtins import raw_input as input

    while True:
        email = input('Enter email for validation: ')

        mx = input('Validate MX record? [yN] ')
        if mx.strip().lower() == 'y':
            mx = True
        else:
            mx = False

        validate = input('Try to contact server for address validation? [yN] ')
        if validate.strip().lower() == 'y':
            validate = True
        else:
            validate = False

        disposable = input('Can the email be disposable? [Yn] ')
        if disposable.strip().lower() == 'n':
            disposable = False
        else:
            disposable = True

        sending_email = input('sending_email? [string] ')

        logging.basicConfig()

        result = validate_email(email, mx, validate, debug=True, smtp_timeout=1,
                                allow_disposable=disposable,
                                sending_email=sending_email)
        if result:
            print("Valid!")
        elif result is None:
            print("I'm not sure.")
        else:
            print("Invalid!")

        time.sleep(1)


if __name__ == "__main__":
    interactive_check()
