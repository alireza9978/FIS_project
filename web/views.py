import json
import subprocess

import requests
from django.http import JsonResponse

# Create your views here.
from web.models import *


def save_attempt(request):
    request = request.META
    data = request
    username = data['USERNAME']
    # password = data['PASSWORD']
    if 'REMOTE_ADDR' in request.keys():
        ip = request['REMOTE_ADDR']
    else:
        ip = None
    if 'HTTP_USER_AGENT' in request.keys():
        user_agent = request['HTTP_USER_AGENT']
    else:
        user_agent = None
    if 'CONTENT_LENGTH' in request.keys():
        content_length = request['CONTENT_LENGTH']
    content_type = request['CONTENT_TYPE']
    if 'HTTP_HOST' in request.keys():
        host = request['HTTP_HOST']
    else:
        host = None
    if 'HTTP_ACCEPT' in request.keys():
        accept = request['HTTP_ACCEPT']
    else:
        accept = None
    if 'HTTP_ACCEPT_LANGUAGE' in request.keys():
        accept_language = request['HTTP_ACCEPT_LANGUAGE']
    else:
        accept_language = None
    if 'HTTP_ACCEPT_ENCODING' in request.keys():
        accept_encoding = request['HTTP_ACCEPT_ENCODING']
    else:
        accept_encoding = None
    if 'SERVER_NAME' in request.keys():
        server_name = request['SERVER_NAME']
    else:
        server_name = None
    if 'SERVER_PORT' in request.keys():
        server_port = request['SERVER_PORT']
    else:
        server_port = None
    if 'HTTP_REFERER' in request.keys():
        referer = request['HTTP_REFERER']
    else:
        referer = None
    if "REQUEST_METHOD" in request.keys():
        method = request["REQUEST_METHOD"]
    else:
        method = 'POST'
    if 'QUERY_STRING' in request.keys():
        query_string = request['QUERY_STRING']
    else:
        query_string = None
    if 'HTTP_COOKIE' in request.keys():
        cookie = request['HTTP_COOKIE']
    else:
        cookie = None
    r = requests.get(url=f"https://ip2c.org/{ip}")
    country = r.content.decode('ascii').split(';')
    country = country[len(country) - 1]

    new_attempt = Attempt(username=username, ip=ip, user_agent=user_agent,
                          content_length=content_length, content_type=content_type, host=host, accept=accept,
                          accept_language=accept_language, accept_encoding=accept_encoding, server_name=server_name,
                          server_port=server_port, referer=referer, method=method, query_string=query_string,
                          cookie=cookie, country=country)
    new_attempt.save()


def register(request):
    save_attempt(request)
    request = json.load(request)
    data = request
    if 'username' not in request.keys():
        return JsonResponse({
            'message': 'Bad credentials'}, status=400)
    elif 'password' not in request.keys():
        return JsonResponse({
            'message': 'Bad credentials'}, status=400)
    if 'email' not in request.keys():
        return JsonResponse({
            'message': 'no email provided'}, status=400)

    username = data['username']
    password = data['password']
    email = data['email']
    new_user = MyUser(username=username, password=password, email=email)
    new_user.save()

    user_count = Username.objects.filter(username=username).count()
    pass_count = Password.objects.filter(password=password).count()
    user_pass_count = UserPassMix.objects.filter(username=username, password=password).count()

    if user_count != 0:
        add_user_name = Username.objects.filter(username=username)
        add_user = add_user_name.first()
        add_user.count = add_user.count + 1
        add_user.save()
    else:
        new_username = Username(username=username, count=1)

    if pass_count != 0:
        add_password = Password.objects.filter(password=password)
        add_password = add_password.first()
        add_password.count = add_password.count + 1
        add_password.save()
    else:
        new_password = Password(password=password, count=1)

    if user_pass_count != 0:
        add_mix = UserPassMix.objects.filter(username=username, password=password)
        add_mix = add_mix.first()
        add_mix.count = add_mix.count + 1
        add_mix.save()
    else:
        userpass = UserPassMix(username=username, password=password, count=1)
    return JsonResponse({'message': 'user registered'}, status=200)


def login(request):
    # save_attempt(request)
    request = json.loads(request)
    data = request
    if 'username' not in data.keys():
        return JsonResponse({
            'message': 'Bad credentials'}, status=400)
    if 'password' not in data.keys():
        return JsonResponse({
            'message': 'Bad credentials'}, status=400)

    username = data['username']
    password = data['password']
    # save_attempt(request=request)

    # username = "mmd"
    # password = "1234"
    #
    # user_name = "afshari"
    # password = "qwer"

    proc = subprocess.Popen(["sudo", "-S", "cat", "/etc/shadow"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE).communicate(input=b'      \n')
    users = proc[0].decode().split("\n")
    user_found = False
    founded_user = None
    for user in users:
        if user.startswith(username + ":"):
            user_found = True
            founded_user = user
            break
    if user_found:
        hashed_password = founded_user[founded_user.index(":") + 1:founded_user.index(":", len(username) + 1)]
        salt = hashed_password.split("$")[-2]
        my_command = 'openssl passwd -6 -salt {}'.format(salt)
        hashed_input_password = subprocess.Popen(my_command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE).communicate(input=(password + "\n").encode())[
                                    0].decode("utf-8")[:-1]
        if hashed_password == hashed_input_password:
            print("user authenticated")
            return JsonResponse({'message': 'login successful'}, status=200)
        else:
            print("wrong password")
            return JsonResponse({'message': 'Bad credentials'}, status=400)
    else:
        print("user not found")
        return JsonResponse({'message': 'user not found'}, status=403)


def files(request):
    # save_attempt(request)
    request = json.load(request)
    data = request
    if 'username' not in data.keys():
        return JsonResponse({
            'message': 'Bad credentials'}, status=400)

    # save_attempt(request=request)

    username = data['username']
    # user = "afshari"

    system_files = subprocess.Popen(["sudo", "-S", "ls", "./files/"],
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE).communicate(input=b'      \n')[0].decode("utf-8").split(
        "\n")[:-1]
    for file_name in system_files:
        command = "sudo -u " + username + " test -r ./files/" + file_name
        result = subprocess.Popen(command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        result.communicate()
        if result.returncode == 0:
            message = "{} have access to {}".format(username, file_name)
            return JsonResponse({'message': message}, status=200)

        else:
            message = "{} doesn't have access to {}".format(username, file_name)
            return JsonResponse({'message': message}, status=200)


def trends(request):
    # save_attempt(request)
    request = json.load(request)
    usernames = Username.objects.order_by('count')
    passwords = Password.objects.order_by('count')
    mix_user_passes = UserPassMix.objects.order_by('count')

    msg = ""
    user_list = list(usernames.values('username', 'count'))
    for username in user_list:
        msg = msg + str(username.username) + str(username.count)
    pass_list = list(passwords.values('password', 'count'))
    for password in pass_list:
        msg = msg + str(password.password) + str(password.count)
    mix_list = list(mix_user_passes.values('username', 'password', 'count'))
    for mix in mix_list:
        msg = msg + str(mix.username) + str(mix.password) + str(mix.count)
    return JsonResponse({'message': msg}, status=200)


def iran(request):
    subprocess.Popen(["sudo", "-S", "iptables", "-A", "INPUT", "-s", "{}", "-j", "DROP"],
                     stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE).communicate(input=b'      \n')
    return JsonResponse({
        "password": "hashed_password"
    })


def iran_deactivate(request):
    pass
