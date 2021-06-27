import subprocess

import requests
from django.http import JsonResponse

# Create your views here.
from FIS_pproject.web.models import Attempt


def save_attempt(request):
    data = request.POST
    username = data['username']
    password = data['password']
    if 'REMOTE_ADDR' in request.META.keys():
        ip = request.META['REMOTE_ADDR']
    else:
        ip = None
    if 'HTTP_USER_AGENT' in request.META.keys():
        user_agent = request.META['HTTP_USER_AGENT']
    else:
        user_agent = None
    if 'CONTENT_LENGTH' in request.META.keys():
        content_length = request.META['CONTENT_LENGTH']
    content_type = request.content_type
    if 'HTTP_HOST' in request.META.keys():
        host = request.META['HTTP_HOST']
    else:
        host = None
    if 'HTTP_ACCEPT' in request.META.keys():
        accept = request.META['HTTP_ACCEPT']
    else:
        accept = None
    if 'HTTP_ACCEPT_LANGUAGE' in request.META.keys():
        accept_language = request.META['HTTP_ACCEPT_LANGUAGE']
    else:
        accept_language = None
    if 'HTTP_ACCEPT_ENCODING' in request.META.keys():
        accept_encoding = request.META['HTTP_ACCEPT_ENCODING']
    else:
        accept_encoding = None
    if 'SERVER_NAME' in request.META.keys():
        server_name = request.META['SERVER_NAME']
    else:
        server_name = None
    if 'SERVER_PORT' in request.META.keys():
        server_port = request.META['SERVER_PORT']
    else:
        server_port = None
    if 'HTTP_REFERER' in request.META.keys():
        referer = request.META['HTTP_REFERER']
    else:
        referer = None
    if "REQUEST_METHOD" in request.META.keys():
        method = request.META["REQUEST_METHOD"]
    else:
        method = 'POST'
    if 'QUERY_STRING' in request.META.keys():
        query_string = request.META['QUERY_STRING']
    else:
        query_string = None
    if 'HTTP_COOKIE' in request.META.keys():
        cookie = request.META['HTTP_COOKIE']
    else:
        cookie = None
    r = requests.get(url=f"https://ip2c.org/{ip}")
    country = r.content.decode('ascii').split(';')
    country = country[len(country) - 1]

    new_attempt = Attempt(username=username, password=password, ip=ip, user_agent=user_agent,
                          content_length=content_length, content_type=content_type, host=host, accept=accept,
                          accept_language=accept_language, accept_encoding=accept_encoding, server_name=server_name,
                          server_port=server_port, referer=referer, method=method, query_string=query_string,
                          cookie=cookie, country=country)
    new_attempt.save()


def register(request):
    data = request.POST
    if 'username' not in data.keys() or 'password' not in data.keys():
        return JsonResponse({
            'message': 'Bad credentials'}, status=400)
    if 'email' not in data.keys():
        return JsonResponse({
            'message': 'no email provided'}, status=400)

    username = data['username']
    password = data['password']
    email = data['email']

    user_count = Username.objects.filter(username=username).count() + 1
    pass_count = Password.objects.filter(password=password).count + 1
    user_pass_count = UserPassMix.objects.filter(username=username, password=password).count + 1
    new_user = MyUser(username=username, password=password, email=email)
    new_user.save()

    new_username = Username(username=username, count=user_count)
    new_username.save()

    new_password = Password(password=password, count=pass_count)
    new_password.save()

    userpass = UserPassMix(username=username, password=password, count=user_pass_count)
    userpass.save()

    save_attempt(request)

    return JsonResponse({'message': 'user registered'}, status=200)


def login(request):
    data = request.POST
    if 'username' not in data.keys() or 'password' not in data.keys():
        return JsonResponse({
            'message': 'Bad credentials'}, status=400)

    username = data['username']
    password = data['password']
    save_attempt(request=request)

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
    data = request.POST
    if 'username' not in data.keys():
        return JsonResponse({
            'message': 'Bad credentials'}, status=400)

    save_attempt(request=request)

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
    save_attempt(request=request)
    usernames = Username.objects.order_by('count')
    passwords = Password.objects.order_by('count')
    mix_user_passes = UserPassMix.objects.order_by('count')
    # list(passwords.values('password', 'count'))
    # list(mix_user_passes.values('username', 'password', 'count'))
    return JsonResponse(list(usernames.values('username', 'count')), status=200)


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
