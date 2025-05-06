# auth_flow/views.py

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated 
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import RegisterSerializer, LoginSerializer , ChangePasswordSerializer ,GetUserSerializer , UpdateUserSerializer , RoleUpdateSerializer  , GetAllPersonInSystemSerializers
from .serializers import EmployeeSerializer, EmployeeNameIdSerializer , CreateEmployeeSerializer , UpdateEmployeeSerializer
# from .serializers import (
#     PasswordResetRequestSerializer,
#     PasswordResetVerifySerializer,
#     PasswordResetSerializer
# )
from .models import AllUsers as User , Employee ,PasswordResetOTP
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.generics import ListAPIView , RetrieveAPIView , CreateAPIView , UpdateAPIView , DestroyAPIView
# Reset Password OTP
import pyotp
from django.core.mail import send_mail
from django.conf import settings
from datetime import datetime, timedelta



class RegisterView(APIView):
    """
    View for user registration.
    Allows any user to register with a POST request.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Save the new user
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    API endpoint for user login.
    Authenticates a user and returns JWT tokens upon successful authentication.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid():
                # Extract username and password from the serializer
                username = serializer.data['username']
                password = serializer.data['password']
                
                # Check if the input is an email or username
                user = None
                if '@' in username:
                    # If it contains '@', it's likely an email, so try fetching user by email
                    try:
                        user = User.objects.get(email=username)
                    except User.DoesNotExist:
                        user = None
                else:
                    # Otherwise, treat it as a username
                    try:
                        user = User.objects.get(username=username)
                    except User.DoesNotExist:
                        user = None

                # Authenticate the user
                if user is not None and user.check_password(password):
                    # Generate tokens if authentication is successful
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'role': user.role,
                        'refresh': str(refresh),
                        'access': str(refresh.access_token)
                    })
                else:
                    # Invalid credentials
                    return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                # Validation error
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Handle unexpected errors
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class LogoutView(APIView):
    """
    Logout the user by blacklisting the refresh token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get the refresh token from the request body (not from Authorization header)
            refresh_token = request.data.get('refresh_token')

            if not refresh_token:
                return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Blacklist the refresh token
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()  # Blacklist the token to prevent further use
            except Exception as e:
                return Response({"error": "Invalid token or already blacklisted"}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class ChangePasswordView(APIView):
    """
    API endpoint for changing user password.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            serializer = ChangePasswordSerializer(data=request.data)
            if serializer.is_valid():
                # Extract old and new passwords from the serializer
                old_password = serializer.data['old_password']
                new_password = serializer.data['new_password']
                
                # Check if the old password is correct
                if not request.user.check_password(old_password):
                    return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)
                
                # Change the password
                request.user.set_password(new_password)
                request.user.save()
                
                return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class GetUserData(APIView):
    """
    API endpoint for getting user details.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Pass the 'request' object to the serializer context
            serializer = GetUserSerializer(request.user, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetAllPersonInSystem(ListAPIView):
    """
    API view to get all users in the system.
    """
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = GetAllPersonInSystemSerializers
    # def get(self, request):
    #     if request.user.role != 'Admin':
    #         return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)
    #     users = User.objects.all()
    #     serializer = GetAllPersonInSystemSerializers(users, many=True)
    #     return Response(serializer.data)
    

class UpdateUserData(APIView):
    """
    API endpoint for updating user details.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Check if the request body is empty
            if not request.data:
                return Response({"message": "No data provided to update"}, status=status.HTTP_400_BAD_REQUEST)

            # Serialize the request data with partial updates
            serializer = UpdateUserSerializer(request.user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "User details updated successfully"}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class UpdateUserRole(APIView):
    """
    Class-based view to update user roles. Only accessible to admin users.
    """

    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        if request.user.role != 'Admin':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)
        else:
            try:
                user = User.objects.get(pk=pk)
            except User.DoesNotExist:
                return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            # Check if the admin is trying to update their own role
            if user == request.user:
                return Response({"detail": "You cannot change your own role."}, status=status.HTTP_400_BAD_REQUEST)

            # Use the RoleUpdateSerializer to validate and update the user role
            serializer = RoleUpdateSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                # Save the updated user role
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
    
    

class EmployeeListView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        if request.user.role != 'Admin':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        employees = Employee.objects.all()
        # Ensure the request object is passed in context
        serializer = EmployeeSerializer(employees, many=True, context={'request': request})
        return Response(serializer.data)



class CreateEmployeeView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def post(self, request):
        if request.user.role != 'Admin':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)
        serializer = CreateEmployeeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmployeeDetailView(APIView):
    
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    
    def get(self, request, pk):
        # Check if the user is an Admin
        if request.user.role != 'Admin' and request.user.role != 'Manager':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Fetch the employee by primary key (pk)
            employee = Employee.objects.get(pk=pk)
            
            # Pass 'request' context to serializer to generate absolute URLs for profile picture
            serializer = EmployeeSerializer(employee, context={'request': request})
            
            # Return the serialized data as the response
            return Response(serializer.data)
        except Employee.DoesNotExist:
            # Handle the case where the employee does not exist
            return Response({'error': 'Employee not found'}, status=status.HTTP_404_NOT_FOUND)
        

    def delete(self, request, pk):
        
        if request.user.role != 'Admin':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        try:
            employee = Employee.objects.get(pk=pk)
            user = employee.user
            user.role = 'User'
            user.save()  # Ensure this saves to the database
            employee.delete()
            message = {'message': 'Employee deleted successfully'}
            return Response(message , status=status.HTTP_204_NO_CONTENT)
        except Employee.DoesNotExist:
            return Response({'error': 'Employee not found'}, status=status.HTTP_404_NOT_FOUND)


class UpdateEmployeeView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    
    def put(self, request, pk):
        
        if request.user.role != 'Admin' and request.user.role != 'Manager':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            employee = Employee.objects.get(pk=pk)
        except Employee.DoesNotExist:
            return Response({'error': 'Employee not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UpdateEmployeeSerializer(employee, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmployeeNameIdView(APIView):

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    
    def get(self, request):
        
        if request.user.role != 'Admin':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        employees = Employee.objects.all()
        serializer = EmployeeNameIdSerializer(employees, many=True)
        return Response(serializer.data)


# Get Full Data For Employee Login
class GetFullDataForEmployeeForLoggedIn(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        if request.user.role != 'Manager':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)
        
        employee = Employee.objects.get(user=request.user)
        serializer = EmployeeSerializer(employee , context={'request': request}) # Pass the request object in context
        return Response(serializer.data)


class GetAllRoleUserOnly(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        if request.user.role != 'Admin':
            return Response({"detail": "You do not have permission to perform this action."}, status=status.HTTP_403_FORBIDDEN)
        
        users = User.objects.filter(role='User')  # Filtering users with role 'User'
        # Pass the request object in context
        serializer = GetUserSerializer(users, many=True, context={'request': request})
        return Response(serializer.data)

class GetUserDetails(RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = GetUserSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

