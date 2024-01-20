# Generated by Django 5.0.1 on 2024-01-20 14:55

import secrets
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0004_usertokenemailvalidation"),
    ]

    operations = [
        migrations.AlterField(
            model_name="usertokenemailvalidation",
            name="token",
            field=models.CharField(
                default=secrets.token_urlsafe,
                max_length=255,
                unique=True,
                verbose_name="token",
            ),
        ),
    ]
