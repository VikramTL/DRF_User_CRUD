
from django.urls import path 
from knox import views as knox_views
from .views import LoginView , UserRegistrationView , GetUserView , UpdateUserView , DeleteUserView , ForgotPasswordAPIView , ChangePasswordView
urlpatterns = [
    path(r'login/',LoginView.as_view(), name="knox_login"),
    path(r'logout/', knox_views.LogoutView.as_view(), name='knox_logout'),
    path(r'logoutall/', knox_views.LogoutAllView.as_view(), name='knox_logoutall'),
    path(r'register/', UserRegistrationView.as_view(), name='user_registration'),
    path(r'get_users/', GetUserView.as_view(), name='users'),
    path(r'update_user/<int:user_id>/', UpdateUserView.as_view(), name="update_user"),
    path(r'delete_user/<int:pk>/', DeleteUserView.as_view() , name="delete_user"),
    path(r'forgot_password/', ForgotPasswordAPIView.as_view() , name="forgot_password"),
    path(r'change_password/', ChangePasswordView.as_view() , name="change_password")
]