# Generated by Django 5.0.1 on 2024-01-23 14:24

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0008_alter_resetpasswordtoken_expires_at_alter_user_email_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="resetpasswordtoken",
            name="expires_at",
            field=models.DateTimeField(
                default=datetime.datetime(
                    2024, 1, 23, 14, 54, 36, 824941, tzinfo=datetime.timezone.utc
                ),
                verbose_name="expires at",
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="first_name",
            field=models.CharField(
                blank=True, max_length=255, null=True, verbose_name="first name"
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="last_name",
            field=models.CharField(
                blank=True, max_length=255, null=True, verbose_name="last name"
            ),
        ),
        migrations.AlterField(
            model_name="user",
            name="username",
            field=models.CharField(
                blank=True, max_length=255, null=True, verbose_name="username"
            ),
        ),
        migrations.AlterField(
            model_name="userdeletionrequests",
            name="delete_date",
            field=models.DateTimeField(
                blank=True,
                default=datetime.datetime(
                    2024, 2, 22, 14, 24, 36, 825875, tzinfo=datetime.timezone.utc
                ),
                null=True,
                verbose_name="delete date",
            ),
        ),
    ]