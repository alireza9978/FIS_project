"""FIS_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from web import views

urlpatterns = [
    path('api/register/', views.RegisterView.as_view(),name='web-register-api'),
    path('api/login/', views.LoginView.as_view(), name='web-login-api'),
    path('api/logout/', views.logout_view, name='web-logout-api'),
    path('api/register/', views.RegisterView.as_view(), name='web-register-api'),
    path('api/files/', views.files, name='web-files-api'),
    path('api/trends/', views.trends, name='web-trends-api'),
    path('api/iran/', views.iran, name='web-iran-api'),
    path('api/iran_deactivate/', views.iran_deactivate, name='web-deactivate-api')
]
