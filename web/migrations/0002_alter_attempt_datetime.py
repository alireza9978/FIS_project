# Generated by Django 3.2.4 on 2021-07-07 08:02

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attempt',
            name='datetime',
            field=models.DateTimeField(default=datetime.datetime(2021, 7, 7, 8, 2, 38, 930305)),
        ),
    ]
