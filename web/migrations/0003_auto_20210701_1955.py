# Generated by Django 3.2.4 on 2021-07-01 19:55

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0002_auto_20210701_1953'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attempt',
            name='datetime',
            field=models.DateTimeField(default=datetime.datetime(2021, 7, 1, 19, 55, 34, 829016)),
        ),
        migrations.AlterField(
            model_name='myuser',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='password',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='username',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='userpassmix',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
