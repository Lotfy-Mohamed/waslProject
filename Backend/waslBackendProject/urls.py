"""
URL configuration for waslBackendProject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from django.contrib import admin
from django.urls import path , include
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/' , include('auth_flow.urls')),
    path('api/home/' , include('home_app.urls')),
    path('api/contact-us/' , include('contact_us.urls')),
    path('api/packages/' , include('packages.urls')),
    path('api/about-us/' , include('about_us.urls')),
    path('api/blog/' , include('blog.urls')),
    path('api/services/' , include('our_service.urls')),
]


# Add this line to the end of the file
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
# This line is used to serve media files during development
# It is not recommended to use this in production
# It is only for development purposes
# The line should be removed before deploying to production
