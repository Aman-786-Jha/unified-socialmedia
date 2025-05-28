from django.urls import path
from .views import TwitterAuthURLView, TwitterCallbackView
from .views import *

urlpatterns = [
    path('admin/signup/',NextGrowthBaseUserSignupView.as_view(),name='signup'),
    path('apis/admin/login/',NextGrowthBaseUserLoginView.as_view(),name='login'),
    path('apis/admin/logout/',UserLogoutView.as_view(),name='logout'),
    path('twitter/connect/', TwitterAuthURLView.as_view(), name='twitter-connect'),
    path('twitter/callback/', TwitterCallbackView.as_view(), name='twitter-callback'),
    path('twitter/callback/api/', TwitterCallbackApiView.as_view(), name='twitter-callback-api'),  # actual API logic
    # path('twitter/verify-code/', TwitterVerifyCodeView.as_view(), name='twitter_verify_code'),
    path('twitter/following/', TwitterFollowingView.as_view(), name='twitter-following'),
    path('twitter/liked-tweets/', TwitterLikedTweetsView.as_view(), name='twitter-liked-tweets'),
    


    ######## webapps
    path('apis/admin/verify/', AdminVerifyAPIView.as_view(), name='token-verify'),
    path('webadmin/admin/login-page/', AdminLoginPageView.as_view(), name='admin-login-page'),
    path('webadmin/admin/dashboard/', AdminDashboardPageView.as_view(), name='admin-login-dashboard'),
]
