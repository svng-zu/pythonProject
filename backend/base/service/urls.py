# from django.urls import path, re_path
# from rest_framework import permissions
# from rest_framework_simplejwt import views as jwt_views

# from .views import *
# from rest_framework_simplejwt.views import TokenRefreshView

# urlpatterns = [
#     path("signup/", SignupAPIView.as_view(), name ='signup'),
#     path("auth/", AuthAPIView.as_view()),
#     #post - login, delete - logout, get - user info
#     path("auth/refresh/", TokenRefreshView.as_view())
# ]

from django.urls import path
from .views import *

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path("signup/", SignupAPIView.as_view(), name = 'signup'), #signup
    path("auth/", LoginView.as_view(), name ='login'), #login
    path("logout/", LogoutView.as_view(), name = 'logout'), #logout

    path('token/', TokenRefreshView.as_view(), name = 'token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name = 'token_refresh'),
]