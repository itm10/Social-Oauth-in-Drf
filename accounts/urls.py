from django.urls import path

from .views import RegisterAPIView, UserInfo, LogoutAPIView, GoogleLogin, callback, \
    callback_github, GithubLogin, RedirectToGoogleAPIView, RedirectToGithubAPIView

urlpatterns = [
    path('register', RegisterAPIView.as_view(), name='register'),
    path('logout', LogoutAPIView.as_view(), name='logout'),
    path('get-user-data/<str:email>', UserInfo.as_view(), name='get-user-data'),
    path('google', GoogleLogin.as_view(), name='google_login'),
    path('google-login', RedirectToGoogleAPIView.as_view(), name='google_login2'),
    path('github-login', RedirectToGithubAPIView.as_view(), name='github_login'),
    path('github', GithubLogin.as_view(), name='github_login'),
    path('google/callback', callback, name='google_callback'),
    path('github/callback', callback_github, name='github_callback'),

]
