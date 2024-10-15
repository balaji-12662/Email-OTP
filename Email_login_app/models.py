from django.db import models
from django.utils.crypto import get_random_string

class User(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    otp_secret = models.CharField(max_length=255, blank=True, null=True)


    def generate_otp_secret(self):
        otp_secret = get_random_string(length=32)
        self.save()
        return otp_secret
