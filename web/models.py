import datetime

from django.db import models


# Create your models here.
class MyUser(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField()
    password = models.CharField(max_length=400)


class Password(models.Model):
    password = models.CharField(max_length=400)
    count = models.IntegerField(default=1)


class Username(models.Model):
    username = models.CharField(max_length=255)
    count = models.IntegerField(default=1)


class UserPassMix(models.Model):
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=400)
    count = models.IntegerField(default=1)


class Attempt(models.Model):
    attempt_id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255, default="")
    password = models.CharField(max_length=255, default="")
    datetime = models.DateTimeField(default=datetime.datetime.now())
    ip = models.GenericIPAddressField(null=False, editable=False, default="")
    user_agent = models.CharField(max_length=511, default="")
    content_length = models.IntegerField(default=0)
    content_type = models.CharField(max_length=255, null=True)
    host = models.URLField(null=True)
    accept = models.CharField(max_length=255, null=True)
    accept_language = models.CharField(max_length=255, null=True)
    accept_encoding = models.CharField(max_length=255, null=True)
    server_name = models.CharField(max_length=255, default="")
    server_port = models.IntegerField(default=0)
    referer = models.URLField(null=True)
    method = models.CharField(max_length=15, default='POST')
    query_string = models.CharField(max_length=255, null=True)
    cookie = models.CharField(max_length=1023, null=True)
    country = models.CharField(max_length=255, null=True)
