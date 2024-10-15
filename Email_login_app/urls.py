
from django.urls import path
from .views import UserLoginView, UserRegistrationView, OTPSendView, OTPVerifyView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('otp/send/', OTPSendView.as_view(), name='otp-send'),
    path('otp/verify/', OTPVerifyView.as_view(), name='otp-verify'),
    path('login/', UserLoginView.as_view(), name='user-login'),

]