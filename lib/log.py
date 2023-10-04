def info(message=''):
    print(f"INFO: {message}")

def warn(message=''):
    print(f"WARN: {message}")

def error(message=''):
    print(f"ERROR: {message}")
    exit(1)

def usr_in(prompt=''):
    return input(prompt + ' ')

def yn(prompt=''):
    usr_in = input(prompt + ' (y/n) ')
    return usr_in in ('y', 'yes')