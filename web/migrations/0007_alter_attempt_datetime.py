# Generated by Django 3.2.4 on 2021-07-06 07:59

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0006_auto_20210704_1949'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attempt',
            name='datetime',
            field=models.DateTimeField(default=datetime.datetime(2021, 7, 6, 7, 59, 1, 758803)),
        ),
    ]
