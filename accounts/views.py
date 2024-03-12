import os
import requests
from django.shortcuts import redirect
from rest_framework.generics import GenericAPIView
from .serializers import RegisterSerializer, UserSerializer, LogoutSerializer
from django.contrib.auth.views import get_user_model
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.models import SocialApp
from dj_rest_auth.registration.views import SocialLoginView
from dotenv import load_dotenv

from rest_framework.response import Response
from rest_framework.decorators import api_view
load_dotenv()
User = get_user_model()


class RegisterAPIView(GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        username = request.data.get('username')
        password = request.data.get('password')
        confirm = request.data.get('confirm')

        if password == confirm:
            if User.objects.filter(username=username).exists():
                return Response({'success': False, 'message': 'Username already exists'}, status=400)
            if User.objects.filter(email=email).exists():
                return Response({'success': False, 'message': 'Email already exists'}, status=400)
            else:
                user = User.objects.create_user(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    username=username,
                    password=password
                )
                user_serializer = UserSerializer(user)
                return Response({'success': True, 'data': user_serializer.data})
        else:
            return Response({"success": False, 'message': 'Password are not same'})


class UserInfo(GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, email):
        query = User.objects.filter(email=email).first()

        if query:
            user_serializer = UserSerializer(query)
            return Response(user_serializer.data)


class LogoutAPIView(GenericAPIView):
    permission_classes = (IsAuthenticated, )
    serializer_class = LogoutSerializer

    def post(self, request):
        refresh_token = request.data.get('refresh')
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response(status=204)


class RedirectToGoogleAPIView(GenericAPIView):

    def get(self, request):
        google_redirect_uri = os.getenv('GOOGLE_REDIRECT_URL')
        try:
            google_client_id = SocialApp.objects.get(provider='google').client_id
        except SocialApp.DoesNotExist:
            return Response({'success': False, 'message': 'SocialApp does not exist'}, status=404)
        url = f'https://accounts.google.com/o/oauth2/v2/auth?redirect_uri={google_redirect_uri}&prompt=consent&response_type=code&client_id={google_client_id}&scope=openid email profile&access_type=offline'
        return redirect(url)


class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = 'https://1ca5-178-218-201-17.ngrok-free.app/accounts/google/callback'
    client_class = OAuth2Client


class RedirectToGithubAPIView(GenericAPIView):
    def get(self, request):
        try:
            github_client_id = SocialApp.objects.get(provider='github').client_id
        except SocialApp.DoesNotExist:
            return Response({'success': False, 'message': 'SocialApp does not exist'}, status=404)
        url = f'https://github.com/login/oauth/authorize?scope=user:email&client_id={github_client_id}'
        return redirect(url)


class GithubLogin(SocialLoginView): # if you want to use Authorization Code Grant, use this
    adapter_class = GitHubOAuth2Adapter
    callback_url = 'https://6232-213-230-66-5.ngrok-free.app/accounts/github/callback'
    client_class = OAuth2Client


@api_view(["GET"])
def callback(request):
    """Callback"""
    code = request.GET.get("code")

    # exchange code with authorization server for access token and ID token
    res = requests.post("http://localhost:8000/accounts/google", data={"code": code}, timeout=30)
    print('Response >>>', res.json())

    # return ID token to the user which will be used by the user in subsequent requests to verify his identity
    return Response(res.json())


@api_view(["GET"])
def callback_github(request):
    """Callback"""
    code = request.GET.get("code")
    print(code)

    # exchange code with authorization server for access token and ID token
    res = requests.post("http://localhost:8000/accounts/github", data={"code": code}, timeout=30)
    print('Response >>>', res.json())

    # return ID token to the user which will be used by the user in subsequent requests to verify his identity
    return Response(res.json())



