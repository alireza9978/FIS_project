import requests

for i in range(100):
    _ = requests.get(url="http://192.168.1.104:8000/login/")
