def info(message=''):
    print(f"INFO: {message}")

def warn(message=''):
    print(f"WARN: {message}")

def error(message=''):
    print(f"ERROR: {message}")

def usr_in(prompt=''):
    return input(f'{prompt}')

def yn(prompt=''):
    usr_in = input(prompt)
    return usr_in in ('y', 'yes')