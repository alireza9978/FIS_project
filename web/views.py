import subprocess

from django.http import JsonResponse


# Create your views here.
def login(request):
    user_name = "mmd"
    password = "1234"

    proc = subprocess.Popen(["sudo", "-S", "cat", "/etc/shadow"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE).communicate(input=b'      \n')
    users = proc[0].decode().split("\n")
    user_found = False
    founded_user = None
    for user in users:
        if user.startswith(user_name + ":"):
            user_found = True
            founded_user = user
            break
    if user_found:
        hashed_password = founded_user[founded_user.index(":") + 1:founded_user.index(":", len(user_name) + 1)]
        salt = hashed_password.split("$")[-2]
        my_command = 'openssl passwd -6 -salt {}'.format(salt)
        hashed_input_password = subprocess.Popen(my_command.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE).communicate(input=(password + "\n").encode())[
                                    0].decode("utf-8")[:-1]
        if hashed_password == hashed_input_password:
            print("user authenticated")

    return JsonResponse({
        "password": "hashed_password"
    })
