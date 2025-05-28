from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .utils import get_twitter_authorization_url, get_twitter_token
from .models import TwitterAccount
import requests




from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import requests

from .models import TwitterAccount
from .utils import get_twitter_authorization_url, get_twitter_token  
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny,IsAuthenticated, IsAdminUser
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema

from .serializers import *
from drf_yasg import openapi
from django.contrib.auth import authenticate
from rest_framework.exceptions import NotFound
from django.http import JsonResponse
from django.views import View
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.parsers import MultiPartParser, FormParser
from drf_yasg import openapi
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import *

class NextGrowthBaseUserSignupView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        request_body=NextGrowthBaseUserSingupSerializer,
    responses={
        201: openapi.Response(description='Created', schema=NextGrowthBaseUserSingupSerializer),
        400: openapi.Response(description='Bad Request', schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
    }
    )

    def post(self, request):
        try:
            serializer = NextGrowthBaseUserSingupSerializer(data=request.data)
            print('data----------->', request.data)
            print('typeserializer--------->', serializer)
            print('typeof----------->', type(serializer))
            
            if serializer.is_valid():
                print('serializer.validated_data----------->', serializer.validated_data)  # ye serialze ke baad dict dikhaayega..ki kaisa aaya
                # serializer.validated_data['is_superuser'] = True

                obj = serializer.save()

                return Response(
                    {
                        'responseCode': status.HTTP_201_CREATED,
                        'responseMessage': "Default developer type user created successfully!",
                        'responseData': {
                            "full_name": obj.full_name,
                            "email": obj.email,
                            "uuid": obj.uuid,
                        }
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'responseMessage': [f"{error[1][0]}" for error in dict(serializer.errors).items()][0],
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except serializers.ValidationError as e:
            return Response(
                {
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'responseMessage': [f"{error[1][0]}" for error in dict(e).items()][0],
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            print("DeveloperSignupView Error -->", e)
            return Response(
                {
                    'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'responseMessage': "Something went wrong! Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class NextGrowthBaseUserLoginView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=NextGrowthBaseUserLoginSerializer,
        responses={
            200: openapi.Response(description='OK', schema=NextGrowthBaseUserLoginSerializer),
            400: openapi.Response(description='Bad Request', schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
            401: openapi.Response(description='Unauthorized', schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
        }
    )
    def post(self, request):
        try:
            serializer = NextGrowthBaseUserLoginSerializer(data=request.data)
            
            if serializer.is_valid():
                email = serializer.validated_data.get('email')
                password = serializer.validated_data.get('password')
                
                if BytequestBaseUser.objects.filter(email=email).exists():
                    user=BytequestBaseUser.objects.get(email=email)
                    
                    if user and user.otp_verify and user.check_password(password) and user.user_type == 'Admin':
                        refresh = RefreshToken.for_user(user)
                        access_token = str(refresh.access_token)
                        refresh_token = str(refresh)
                        user.is_active=True
                        user.login_status=True
                        user.save()
                        return Response(
                            {
                                'responseCode': status.HTTP_200_OK,
                                'responseMessage': "Login successful",
                                'responseData': {
                                    "full_name": user.full_name,
                                    "email": user.email,
                                    "uuid": user.uuid,
                                    'access_token': access_token,
                                    'refresh_token': refresh_token
                                }
                            },
                            status=status.HTTP_200_OK
                        )
                    elif user and not user.otp_verify:
                        return Response(
                            {
                                'responseCode': status.HTTP_400_BAD_REQUEST,
                                'responseMessage': "OTP not verified",
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    elif user.user_type != 'Admin':
                        return Response(
                            {
                                'responseCode': status.HTTP_400_BAD_REQUEST,
                                'responseMessage': "You are not allowed to perform this action.",
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    return Response(
                        {
                            'responseCode': status.HTTP_401_UNAUTHORIZED,
                            'responseMessage': "Invalid credentials",
                        },
                        status=status.HTTP_401_UNAUTHORIZED
                    )

                return Response(
                        {
                            'responseCode': status.HTTP_401_UNAUTHORIZED,
                            'responseMessage': "User Is not Valid",
                        },
                        status=status.HTTP_401_UNAUTHORIZED
                    )
            return Response(
                {
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'responseMessage': [f"{error[1][0]}" for error in dict(serializer.errors).items()][0],
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            

        except serializers.ValidationError as e:
            return Response(
                {
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'responseMessage': [f"{error[1][0]}" for error in dict(e).items()][0],
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            print("LoginView Error -->", e)
            return Response(
                {
                    'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'responseMessage': "Something went wrong! Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                default='Bearer ',
                description='Bearer Token',
            ),
        ],
        responses={
            200: openapi.Response(description='OK'),
            401: openapi.Response(description='Unauthorized', schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
        }
    )
    def post(self, request):
        try:
            user = request.user

            if not user.login_status:
                return Response(
                    {
                        'responseCode': status.HTTP_400_BAD_REQUEST,
                        'responseMessage': "User already logged out",
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )


            user.login_status = False
            user.is_active = False
            user.save()

            return Response(
                {
                    'responseCode': status.HTTP_200_OK,
                    'responseMessage': "Logout successful",
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            print("LogoutView Error -->", e)
            return Response(
                {
                    'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'responseMessage': "Something went wrong! Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TwitterAuthURLView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get Twitter Authorization URL",
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                description='Bearer access token (e.g., Bearer <token>)'
            )
        ],
        responses={
            200: openapi.Response(description="Authorization URL returned successfully."),
            401: "Unauthorized"
        }
    )
    def get(self, request):
        try:
            auth_url = get_twitter_authorization_url(request)
            return Response({"auth_url": auth_url}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





from rest_framework.views import APIView
from django.shortcuts import render

class TwitterCallbackView(APIView):
    def get(self, request):
        return render(request, 'twitterapi/oauth-template.html')
    



class TwitterCallbackApiView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        state = request.query_params.get("state")
        code = request.query_params.get("code")

        if not code:
            return Response({"error": "Code not provided"}, status=status.HTTP_400_BAD_REQUEST)

        token_data = get_twitter_token(code)

        if "access_token" not in token_data:
            return Response({"error": token_data}, status=status.HTTP_400_BAD_REQUEST)

        access_token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info = requests.get("https://api.twitter.com/2/users/me", headers=headers).json()

        twitter_user_id = user_info.get("data", {}).get("id")
        screen_name = user_info.get("data", {}).get("username")

        user = request.user

        TwitterAccount.objects.update_or_create(
            user=user,
            defaults={
                "twitter_user_id": twitter_user_id,
                "screen_name": screen_name,
                "access_token": access_token,
                "refresh_token": token_data.get("refresh_token"),
                "token_type": token_data.get("token_type"),
                "expires_in": token_data.get("expires_in"),
            }
        )

        return Response({"message": "Twitter account connected successfully."}, status=status.HTTP_200_OK)



class TwitterFollowingView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Handle Twitter OAuth Callback",
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=False,
                description='Bearer access token (for authenticated users)'
            )
        ],
        responses={
            200: openapi.Response(description="Twitter account connected successfully."),
            400: "Bad Request / Missing Code or Token Error",
            401: "Unauthorized",
        }
    )

    def get(self, request):
        try:
            twitter_account = TwitterAccount.objects.get(user=request.user)
        except TwitterAccount.DoesNotExist:
            return Response({"error": "Twitter account not connected."}, status=status.HTTP_404_NOT_FOUND)
        
        twitter_user_id = twitter_account.twitter_user_id
        access_token = twitter_account.access_token

        url = f"https://api.twitter.com/2/users/{twitter_user_id}/following"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        params = {
            "max_results": 100,  
            "user.fields": "id,name,username,profile_image_url"
        }

        response = requests.get(url, headers=headers, params=params)
        if response.status_code != 200:
            return Response({"error": "Failed to fetch following list", "details": response.json()}, status=response.status_code)

        data = response.json()
        return Response(data, status=status.HTTP_200_OK)



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
import requests

class TwitterLikedTweetsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Handle Twitter OAuth Callback",
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=False,
                description='Bearer access token (for authenticated users)'
            )
        ],
        responses={
            200: openapi.Response(description="Twitter account connected successfully."),
            400: "Bad Request / Missing Code or Token Error",
            401: "Unauthorized",
        }
    )

    def get(self, request):

        try:
            print('request.user----------->', request.user)
            twitter_account = TwitterAccount.objects.get(user=request.user)
        except TwitterAccount.DoesNotExist:
            return Response({"error": "Twitter account not connected."}, status=status.HTTP_404_NOT_FOUND)

        twitter_user_id = twitter_account.twitter_user_id
        access_token = twitter_account.access_token

        url = f"https://api.twitter.com/2/users/{twitter_user_id}/liked_tweets"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        params = {
            "max_results": 100,  
            "tweet.fields": "id,text,created_at,author_id",
            
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            return Response({"error": "Failed to fetch liked tweets", "details": response.json()}, status=response.status_code)

        return Response(response.json(), status=status.HTTP_200_OK)



class AdminLoginPageView(View):
    template_name = 'twitterapi/login.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
    
class AdminDashboardPageView(View):

    template_name = 'twitterapi/dashboard.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
    


class AdminVerifyAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.user_type == "Admin":
            return Response({"status": True, "full_name": user.full_name})
        return Response({"status": False, "message": "Not an admin"}, status=403)