from rest_framework.views import APIView
from knox.models import AuthToken
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework import status
from .serializers import LoginSerializer
from django.contrib.auth import authenticate
from .serializers import UserSerializer , GetUserSerializer , UserPatchSerializer , ForgotPasswordSerializer , UpdatePasswordSerializer
from rest_framework import generics
from .models import User
from knox.auth import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
import os
from dotenv import load_dotenv
load_dotenv()


class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
            serializer = LoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            user = authenticate(request=request, email=email, password=password)

            if user is not None:
                auth_token = AuthToken.objects.create(user)[1]
                return Response({'token': auth_token}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class UserRegistrationView(APIView):

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message':"User registered Successfully"}, status=status.HTTP_201_CREATED)
    

class GetUserView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.all()
        serialized = GetUserSerializer(users, many=True)
        return Response({'data': serialized.data}, status=status.HTTP_200_OK)

class UpdateUserView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request, user_id):
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserPatchSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'User updated successfully'}, status=status.HTTP_200_OK)
        return Response({'message':serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class DeleteUserView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return Response({'message': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
class ForgotPasswordAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        auth_token = AuthToken.objects.create(user)[1]
        reset_password_link = f"{os.getenv('BASE_URL')}/change_password/{auth_token}/"
        send_mail(
            'Password Reset',
            f'Click the following link to reset your password: {reset_password_link}',
            'hanishtlgt@gmail.com',
            [user.email],
            fail_silently=False,
        )

        return Response({'success': 'Password reset link sent successfully'}, status=status.HTTP_200_OK)
    
class ChangePasswordView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        serializer = UpdatePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data['new_password']
        try:
            user = User.objects.get(email=request.user)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        user.set_password(password)
        user.save()
        user_token = request.auth
        try:
            user_token.delete()
        except AuthToken.DoesNotExist:
            return Response({'error': 'Token not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'success': 'Password updated successfully.'}, status=status.HTTP_200_OK)
        



    
     



