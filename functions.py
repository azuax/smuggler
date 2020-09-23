from lib.colorama import Fore, Style
import re

NOCOLOR = None

def CF(text):
    global NOCOLOR
    if NOCOLOR:
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        text = ansi_escape.sub('', text)
    return text


def process_uri(uri):
    #remove shouldering white spaces and go lowercase
    uri = uri.strip().lower()

    #if it starts with https:// then strip it
    if ((len(uri) > 8) and (uri[0:8] == "https://")):
        uri = uri[8:]
        ssl_flag = True
        std_port = 443
    elif ((len(uri) > 7) and (uri[0:7] == "http://")):
        uri = uri[7:]
        ssl_flag = False
        std_port = 80
    else:
        print_info("Error malformed URL not supported: %s" % (Fore.CYAN + uri))
        exit(1)

    #check for any forward slashes and filter only domain portion
    uri_tokenized = uri.split("/")
    uri = uri_tokenized[0]
    smendpoint = '/' + '/'.join(uri_tokenized[1:])

    #check for any port designators
    uri = uri.split(":")

    if len(uri) > 1:
        return (uri[0], int(uri[1]), smendpoint, ssl_flag)

    return (uri[0], std_port, smendpoint, ssl_flag)


def print_info(msg, file_handle=None):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    msg = Style.BRIGHT + Fore.MAGENTA + "[%s] %s"%(Fore.CYAN+'+'+Fore.MAGENTA, msg) + Style.RESET_ALL
    plaintext = ansi_escape.sub('', msg)
    print(CF(msg))
    if file_handle is not None:
        file_handle.write(plaintext+"\n")


def banner(sm_version):
    print(CF(Fore.CYAN))
    print(CF(r"  ______                         _              "))
    print(CF(r" / _____)                       | |             "))
    print(CF(r"( (____  ____  _   _  ____  ____| | _____  ____ "))
    print(CF(r" \____ \|    \| | | |/ _  |/ _  | || ___ |/ ___)"))
    print(CF(r" _____) ) | | | |_| ( (_| ( (_| | || ____| |    "))
    print(CF(r"(______/|_|_|_|____/ \___ |\___ |\_)_____)_|    "))
    print(CF(r"                    (_____(_____|               "))
    print(CF(r""))
    print(CF(r"     @defparam                         %s"%(sm_version)))
    print(CF(Style.RESET_ALL))