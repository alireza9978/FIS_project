from django.contrib import admin
from django.contrib.auth.models import User

from web.models import *

# Register your models here.
admin.site.register(MyUser)
admin.site.register(Password)
admin.site.register(Username)
admin.site.register(UserPassMix)
admin.site.register(Attempt)

