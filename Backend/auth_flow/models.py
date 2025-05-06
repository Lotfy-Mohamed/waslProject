from django.db import models


# Import AbstractUser
from django.contrib.auth.models import AbstractUser  , PermissionManager , Permission
from django.contrib.contenttypes.models import ContentType
from datetime import datetime, timedelta


ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Manager', 'Manager'),
        ('User', 'User'),
    ]
    
class AllUsers(AbstractUser):
    phone = models.CharField(max_length=15, blank=True)
    role = models.CharField(
        max_length=10, 
        choices=ROLE_CHOICES, 
        default='User',
        null=True
    )
    date_joined = models.DateTimeField(auto_now_add=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    country = models.CharField(max_length=255, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    

    def save(self, *args, **kwargs):
        if self.role == 'Admin':
            self.is_staff = True
            self.is_superuser = True
        elif self.role == 'Manager':
            self.is_staff = True
            self.is_superuser = False
        else:
            self.is_staff = False
            self.is_superuser = False
        super().save(*args, **kwargs)

    def __str__(self):
        # return f"{self.username} ({self.role})"
        return f"{self.username}"



class Employee(models.Model):
    user = models.OneToOneField(AllUsers, on_delete=models.CASCADE)
    position = models.CharField(max_length=255)
    company_name = models.CharField(max_length=255)

    def save(self , *args , **kwargs):
        self.user.role = 'Manager'
        self.user.save()
        super().save(*args , **kwargs)

    def __str__(self):
        return f"{self.user.username}"
    
    
    
    
class PasswordResetOTP(models.Model):
    user = models.ForeignKey(AllUsers, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    expiry_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return datetime.now() > self.expiry_time

    def __str__(self):
        return f"OTP for {self.user.email}" 