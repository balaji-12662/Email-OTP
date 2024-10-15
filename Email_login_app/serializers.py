# myapp/serializers.py

from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']


from rest_framework import serializers

class OTPSerializer(serializers.Serializer):
    otp = serializers.CharField()

