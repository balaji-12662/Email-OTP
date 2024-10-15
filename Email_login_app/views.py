import pyotp 
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User
from .serializers import UserSerializer
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User
from .serializers import UserSerializer

class UserRegistrationView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Send welcome and success emails
            self.send_welcome_email(user)
            self.send_success_email(user)

            return Response(
                {
                    'message': 'User registered successfully',
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'password': user.password,
                },
                status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_welcome_email(self, user):
        subject = 'Welcome to Your Website'
        message = f'Hiii, {user.username},Your user name is {user.username} and password is {user.password}. Thank you, for registering on Your Website!'
        from_email = settings.DEFAULT_FROM_EMAIL
        #to_email = ['balajichoudhari1112@gmail.com']
        to_email = [user.email]


        send_mail(subject, message, from_email, to_email)

    def send_success_email(self, user):
        subject = 'Registration Success'
        message = f'Hi {user.username}... Your user name is {user.username} and password is {user.password}. Your registration on Your Website was successful!'
        from_email = settings.DEFAULT_FROM_EMAIL
        #to_email = ['balajichoudhari1112@gmail.com']
        to_email = [user.email]


        send_mail(subject, message, from_email, to_email)


class OTPSendView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email', None)

        if not email:
            return Response({'error': 'Email is required for OTP verification.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Generate and send OTP
        otp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(otp_secret)
        otp = totp.now()

        subject = 'OTP for Verification'
        message = f'Your OTP for verification is: {otp}'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [user.email]

        send_mail(subject, message, from_email, to_email)

        # Save the OTP secret to the user model
        user.otp_secret = otp_secret
        user.save()

        return Response({'message': 'OTP sent successfully.'}, status=status.HTTP_200_OK)

# class OTPVerifyView(APIView):
#     def post(self, request, *args, **kwargs):
#         email = request.data.get('email', None)
#         user_input_otp = request.data.get('otp', None)

#         if not email or not user_input_otp:
#             return Response({'error': 'Email and OTP are required for verification.'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

#         # Verify OTP only if otp_secret is not None
#         if user.otp_secret:
#             totp = pyotp.TOTP(user.otp_secret)
#             is_valid_otp = totp.verify(user_input_otp)

#             if is_valid_otp:
#                 return Response({'message': 'OTP verification successful.'}, status=status.HTTP_200_OK)
#             else:
#                 return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
#         else:
#             return Response({'error': 'OTP verification failed. OTP secret not set.'}, status=status.HTTP_400_BAD_REQUEST)

import pyotp
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User

class OTPVerifyView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email', None)
        user_input_otp = request.data.get('otp', None)

        if not email or not user_input_otp:
            return Response({'error': 'Email and OTP are required for verification.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Verify OTP only if otp_secret is not None
        if user.otp_secret:
            totp = pyotp.TOTP(user.otp_secret)
            is_valid_otp = totp.verify(user_input_otp, valid_window=1)

            if is_valid_otp:
                return Response({'message': 'OTP verification successful.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'OTP verification failed. OTP secret not set.'}, status=status.HTTP_400_BAD_REQUEST)


from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny

class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email', None)
        user_input_otp = request.data.get('otp', None)

        if not email or not user_input_otp:
            return Response({'error': 'Email and OTP are required for login.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Verify OTP only if otp_secret is not None
        if user.otp_secret:
            totp = pyotp.TOTP(user.otp_secret)
            is_valid_otp = totp.verify(user_input_otp)

            if is_valid_otp:
                # Authenticate user
                user = authenticate(email=email, password=user.password)
                if user is not None:
                    auth_login(request, user)
                    token, _ = Token.objects.get_or_create(user=user)
                    # Send login success email
                    self.send_login_email(user)
                    return Response({'message': f'{user.username} logged in successfully.', 'token': token.key}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'OTP verification failed. OTP secret not set.'}, status=status.HTTP_400_BAD_REQUEST)

    def send_login_email(self, user):
        subject = 'Login Successful'
        message = f'Hi {user.username}, You have successfully logged in to Your Website.'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [user.email]

        send_mail(subject, message, from_email, to_email)
