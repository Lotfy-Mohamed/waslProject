# auth_flow/serializers.py

# from django.contrib.auth.models import User
from auth_flow.models import AllUsers as User , Employee , PasswordResetOTP
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
# from django.core.mail import send_mail
# from datetime import datetime, timedelta
# import random


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for registering a new user.
    Validates unique email, matching passwords, and required fields.
    """
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]  # Ensure email is unique
    )
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]  # Enforce strong password
    )
    password2 = serializers.CharField(write_only=True, required=True)  # Confirm password field

    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email', 'first_name', 'last_name' , 'phone','profile_picture' , 'country' , 'date_of_birth')

    def validate(self, attrs):
        # Check if the two passwords match
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        # Create the user with the provided data

        profile_picture = validated_data.pop('profile_picture', None) # Remove profile_picture from validated_data if present and store it in a separate variable       
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone=validated_data['phone'],
            # profile_picture=validated_data['profile_picture'],
            country=validated_data['country'],
            date_of_birth=validated_data['date_of_birth']
        )
            # If profile_picture is provided, set it
        if profile_picture:
            user.profile_picture = profile_picture
        
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)

    def validate(self, attrs):
        # Check if the two new passwords match
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "New passwords didn't match."})
        return attrs


class GetUserSerializer(serializers.ModelSerializer):
    """
    Serializer for getting user details.
    """
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'role', 'first_name', 'last_name', 'phone', 'profile_picture' , 'country' , 'date_of_birth')

    def get_profile_picture(self, obj):
        request = self.context.get('request')  # Get the request object
        if obj.profile_picture:  # Only build the URL if profile_picture is not None
            return request.build_absolute_uri(obj.profile_picture.url) if request else obj.profile_picture.url
        return None


class GetAllPersonInSystemSerializers(serializers.ModelSerializer):
    """
    Serializer for listing all users in the system.
    This directly serializes the User model fields.
    """
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'role', 'first_name', 'last_name', 'phone', 'profile_picture', 'country', 'date_of_birth')

    def get_profile_picture(self, obj):
        request = self.context.get('request')  # Get the request object
        if obj.profile_picture:
            return request.build_absolute_uri(obj.profile_picture.url)  # Construct the absolute URL
        return None


class UpdateUserSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user details.
    """
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'phone' , 'profile_picture' , 'country' , 'date_of_birth')

class RoleUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating the role of a user.
    Ensures the role is one of the valid choices.
    """

    ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Manager', 'Manager'),
        ('User', 'User')
    ]

    role = serializers.ChoiceField(choices=ROLE_CHOICES)

    class Meta:
        model = User
        fields = ['role']  # Only allow the role field to be updated

    def validate_role(self, value):
        """
        You can add any additional validation for the role here if needed.
        """
        return value
    

class EmployeeSerializer(serializers.ModelSerializer):
    user = GetUserSerializer()
    class Meta:
        model = Employee
        fields = '__all__'

class CreateEmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = '__all__'

class EmployeeNameIdSerializer(serializers.ModelSerializer):
    
    user = GetUserSerializer()
    
    class Meta:
        model = Employee
        fields = ['id', 'user']


class UpdateEmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employee
        fields = '__all__'
