import subprocess

import pandas as pd
import requests
from django.contrib.auth import logout, login
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import views, permissions, authentication
from rest_framework.decorators import api_view

# Create your views here.
from web.models import *

unix_password = "12345678"


class CsrfExemptSessionAuthentication(authentication.SessionAuthentication):
    def enforce_csrf(self, request):
        return


def save_trends(username, password):
    user_count = Username.objects.filter(username=username).count()
    pass_count = Password.objects.filter(password=password).count()
    user_pass_count = UserPassMix.objects.filter(username=username, password=password).count()

    if user_count != 0:
        add_user_name = Username.objects.filter(username=username)
        add_user = add_user_name.first()
        add_user.count = add_user.count + 1
        add_user.save()
    else:
        new_username = Username.objects.create(username=username, count=1)

    if pass_count != 0:
        add_password = Password.objects.filter(password=password)
        add_password = add_password.first()
        add_password.count = add_password.count + 1
        add_password.save()
    else:
        new_password = Password.objects.create(password=password, count=1)

    if user_pass_count != 0:
        add_mix = UserPassMix.objects.filter(username=username, password=password)
        add_mix = add_mix.first()
        add_mix.count = add_mix.count + 1
        add_mix.save()
    else:
        userpass = UserPassMix.objects.create(username=username, password=password, count=1)


def get_client_ip(requestmeta):
    x_forwarded_for = requestmeta.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = requestmeta.get('REMOTE_ADDR')
    return ip


def save_attempt(request):
    username = request.data['username']
    password = request.data['password']
    request = request.META
    data = request
    save_trends(username=username, password=password)
    # if 'REMOTE_ADDR' in request.keys():
    #     ip = request['REMOTE_ADDR']
    # else:
    #     ip = None
    ip = get_client_ip(request)
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
    country = r.content.decode('utf8').split(';')
    country = country[len(country) - 1]
    # country = "IR"

    new_attempt = Attempt(username=username, ip=ip, user_agent=user_agent,
                          content_length=content_length, content_type=content_type, host=host, accept=accept,
                          accept_language=accept_language, accept_encoding=accept_encoding, server_name=server_name,
                          server_port=server_port, referer=referer, method=method, query_string=query_string,
                          cookie=cookie, country=country)
    new_attempt.save()


class RegisterView(views.APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (CsrfExemptSessionAuthentication,)

    def post(self, request):
        save_attempt(request)
        # request = json.load(request)

        if 'username' not in request.data.keys():
            return JsonResponse({
                'message': 'Bad credentials'}, status=400)
        elif 'password' not in request.data.keys():
            return JsonResponse({
                'message': 'Bad credentials'}, status=400)
        if 'email' not in request.data.keys():
            return JsonResponse({
                'message': 'no email provided'}, status=400)

        username = request.data['username']
        password = request.data['password']
        email = request.data['email']
        new_user = MyUser.objects.create_user(username=username, password=password, email=email)
        new_user.save()
        return JsonResponse({'message': 'user registered'}, status=200)


class LoginView(views.APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (CsrfExemptSessionAuthentication,)

    def post(self, request):
        save_attempt(request)
        if 'username' not in request.data.keys():
            return JsonResponse({
                'message': 'Bad credentials'}, status=400)
        if 'password' not in request.data.keys():
            return JsonResponse({
                'message': 'Bad credentials'}, status=400)

        username = request.data['username']
        password = request.data['password']
        # save_attempt(request=request)

        # username = "mmd"
        # password = "1234"
        #
        # user_name = "afshari"
        # password = "qwer"

        proc = subprocess.Popen(["sudo", "-S", "cat", "/etc/shadow"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE).communicate(input="{}\n".format(unix_password).encode())

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
                                                     stderr=subprocess.PIPE).communicate(
                input=(password + "\n").encode())[
                                        0].decode("utf-8")[:-1]
            if hashed_password == hashed_input_password:
                print("user authenticated")
                try:
                    django_user = MyUser.objects.get(username=username)
                except MyUser.DoesNotExist:
                    django_user = MyUser.objects.create_user(username=username, password=password)
                login(request, django_user)
                return JsonResponse({'message': 'login successful'}, status=200)
            else:
                print("wrong password")
                return JsonResponse({'message': 'Bad credentials'}, status=400)
        else:
            print("user not found")
            return JsonResponse({'message': 'user not found'}, status=403)


def main_page(request):
    if request.user.is_authenticated:
        return JsonResponse({'message': "hi"}, status=200)
    else:
        return render(request, 'login.html', status=200)


@api_view(['GET'])
@login_required()
def files(request):
    # save_attempt(request)
    # if 'username' not in request.data.keys():
    #     return JsonResponse({
    #         'message': 'Bad credentials'}, status=400)
    # save_attempt(request=request)
    username = request.user.username
    # user = "afshari"

    system_files = subprocess.Popen(["sudo", "-S", "ls", "./files/"],
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE).communicate(input="{}\n".format(unix_password).encode())[
                       0].decode(
        "utf-8").split(
        "\n")[:-1]

    message = []
    for file_name in system_files:
        command = "sudo -u " + username + " test -r ./files/" + file_name
        result = subprocess.Popen(command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        result.communicate()
        if result.returncode == 0:
            message.append("{} have access to {}".format(username, file_name))
        else:
            message.append("{} doesn't have access to {}".format(username, file_name))

    return JsonResponse({'message': message}, status=200)


@api_view(['GET'])
@login_required()
def trends(request):
    # save_attempt(request)
    # request = json.load(request)
    # data = request
    usernames = Username.objects.order_by('count')
    passwords = Password.objects.order_by('count')
    mix_user_passes = UserPassMix.objects.order_by('count')

    msg = []
    user_list = list(usernames.values('username', 'count'))
    msg_srt = "usernames: "
    for username in user_list:
        msg_srt = msg_srt + "username: " + str(username['username']) + "count: " + str(username['count'])
    msg.append(msg_srt)
    pass_list = list(passwords.values('password', 'count'))
    msg_srt = "passwords: "
    for password in pass_list:
        msg_srt = msg_srt + "password: " + str(password['password']) + "count: " + str(password['count'])
    msg.append(msg_srt)
    mix_list = list(mix_user_passes.values('username', 'password', 'count'))
    msg_srt = "mixes: "
    for mix in mix_list:
        msg_srt = msg_srt + "username: " + str(mix['username']) + "password: " + str(mix['password']) + "count: " + str(
            mix['count'])
    msg.append(msg_srt)
    return JsonResponse({'message': msg}, status=200)


@api_view(['GET'])
@login_required()
def iran(request):
    # save_attempt(request)
    ip_df = pd.read_csv("iran_ip.csv")

    drop_all_cmd = [["sudo", "-S", "iptables", "-P", "INPUT", "DROP"],
                    ["sudo", "-S", "iptables", "-P", "FORWARD", "DROP"],
                    ["sudo", "-S", "iptables", "-P", "OUTPUT", "ACCEPT"],
                    ["sudo", "-S", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                    ["sudo", "-S", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                    ["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]]
    for cmd in drop_all_cmd:
        subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(
            input="{}\n".format(unix_password).encode())

    for i, row in ip_df.iterrows():
        target_ip = str(row.values[0]) + "/" + str(row.values[1])
        subprocess.Popen(["sudo", "-S", "iptables", "-A", "INPUT", "-s", target_ip, "-j", "ACCEPT"],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE).communicate(input="{}\n".format(unix_password).encode())

    return JsonResponse({'message:': 'blocked not iran request'}, status=200)


@api_view(['GET'])
@login_required()
def iran_deactivate(request):
    flush_all_cmd = [["sudo", "-S", "iptables", "-F", "INPUT"],
                     ["sudo", "-S", "iptables", "-P", "INPUT", "ACCEPT"],
                     ["sudo", "-S", "iptables", "-F", "FORWARD"],
                     ["sudo", "-S", "iptables", "-P", "FORWARD", "ACCEPT"],
                     ["sudo", "-S", "iptables", "-F", "OUTPUT"],
                     ["sudo", "-S", "iptables", "-P", "OUTPUT", "ACCEPT"]]
    for cmd in flush_all_cmd:
        subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(
            input="{}\n".format(unix_password).encode())
    return JsonResponse({'message:': 'unblocked not iran request'}, status=200)


@api_view(['GET'])
def logout_view(request):
    if request.user.is_authenticated:
        logout(request)
    return JsonResponse({'message': 'logout successfully'}, status=200)
