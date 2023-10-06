import sys

# the verbose option indicates that this message will only appear in verbose mode
# verbose mode is defined to be true if '-v' or '--verbose' exists in sys.argv

# Recommended that level be one of INFO, WARN, ERROR, DEBUG
def disp_message(level, message, verbose):
    statement = f"{level}: {message}"
    # colorize the statement if warn or error level
    if level == 'WARN':
        statement = f"\033[93m{statement}\033[00m" # yellow
    elif level == 'ERROR':
        statement = f"\033[91m {statement}\033[00m" # red

    if not verbose:
        print(statement)
    elif is_verbose: # if we are in verbose mode
        print(f'V {statement}')
    # else, it requires verbose mode to print but we're not in verbose mode

def info(message='', verbose=False):
    disp_message('INFO', message, verbose)

def warn(message='', verbose=False):
    disp_message('WARN', message, verbose)

def error(message='', verbose=False):
    disp_message('ERROR', message, verbose)
    exit(1)

# assumes we're in debug mode if sys.argv contains '--debug'
# else, do nothing
def debug(message=''):
    if is_debug:
        disp_message('DEBUG', message, verbose=False)

def usr_in(prompt=''):
    return input(prompt + ' ')

def yn(prompt=''):
    usr_in = input(prompt + ' (y/n) ')
    return usr_in in ('y', 'yes')

def is_verbose():
    return '-v' in sys.argv or '--verbose' in sys.argv

def is_debug():
    return '--debug' in sys.argv
