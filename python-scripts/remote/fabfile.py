import getpass

from fabric import task, Config
from fabric.group import SerialGroup, ThreadingGroup, GroupException

# Read ip addr from file.
def get_ip(filename:str, n: int) -> list:
    with open(filename) as file:
        lines = file.readlines()
        lines = [line.split(':')[0] for line in lines]
    return lines[:n]

def connect_config(n):
    # remote ip address.
    ip_array = get_ip('../../remoteAddress.txt', int(n))
    # remote connect config.
    sudo_user = getpass.getpass("What's your sudo username?\n")
    sudo_pass = getpass.getpass("What's your sudo password?\n")
    config = Config(overrides={'sudo': {'password': sudo_pass}})
    return ip_array, sudo_user, sudo_pass, config

# connect test
@task
def connect(context, n):
    del context
    ip_array, sudo_user, sudo_pass, config = connect_config(n)
    group = SerialGroup(*ip_array, user=sudo_user, connect_kwargs={'password': sudo_pass}, config=config)
    # run who am i
    group.run("whoami")

# update repo
@task
def update(context, n):
    del context
    ip_array, sudo_user, sudo_pass, config = connect_config(n)
    group = SerialGroup(*ip_array, user=sudo_user, connect_kwargs={'password': sudo_pass}, config=config)
    group.run('rm -rf SimpleAsyncBFT')
    group.run('git clone https://gitee.com/zhazhalaila/SimpleAsyncBFT.git')

# start remote server
@task
def start(context, n, f):
    del context
    ip_array, sudo_user, sudo_pass, config = connect_config(n)
    group = ThreadingGroup(*ip_array, user=sudo_user, connect_kwargs={'password': sudo_pass}, config=config)
    group.run("bash -c 'cd SimpleAsyncBFT && pwd'")
    # if server has been created, kill it.
    try:
        group.sudo('fuser -k 8000/tcp')
    except GroupException:
        print('8000 port has not run process.')
    # change file permission access.
    group.sudo("bash -c 'cd SimpleAsyncBFT/server && chmod u+x server'")
    # start server with parameter.
    id = 0
    for conn in group:
        conn.run('./server -n={} -f={} -id={}'.format(n, f, id))
        id += 1