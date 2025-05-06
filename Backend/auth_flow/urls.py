# auth_flow/urls.py

from django.urls import path
from .views import RegisterView, LoginView, LogoutView , ChangePasswordView , GetUserData , UpdateUserData , UpdateUserRole , GetAllPersonInSystem 
from .views import EmployeeListView, EmployeeDetailView, EmployeeNameIdView , GetAllRoleUserOnly , CreateEmployeeView , GetUserDetails , GetFullDataForEmployeeForLoggedIn , UpdateEmployeeView
# from .views import PasswordResetRequestView, PasswordResetVerifyView, PasswordResetView



# Define URL patterns for authentication endpoints
urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),  # Registration endpoint
    path('login', LoginView.as_view(), name='login'),           # Login endpoint
    path('logout', LogoutView.as_view(), name='logout'),        # Logout endpoint
    path('change-password', ChangePasswordView.as_view(), name='change-password'),  # Change password endpoint
    path('get-user-data', GetUserData.as_view(), name='get-user-data'),  # Get user data endpoint
    path('update-user-data', UpdateUserData.as_view(), name='update-user-data'),  # Update user data endpoint
    path('role-update/<int:pk>', UpdateUserRole.as_view(), name='role-update'),  # Role update endpoint
    path('all-person-in-system', GetAllPersonInSystem.as_view(), name='all-person-in-system'),  # Get all person in system endpoint
    path('get-user-details/<int:pk>', GetUserDetails.as_view(), name='get-user-details'),  # Get user details endpoint
    # Endpoint to get all employees 
    path('employees', EmployeeListView.as_view(), name='employee-list'),
    # Endpoint to get all employees with full data
    path('employees/full-logged', GetFullDataForEmployeeForLoggedIn.as_view(), name='employee-full'),
    # Endpoint to create a new employee
    path('employees/create', CreateEmployeeView.as_view(), name='employee-create'),
    # Endpoint to get, or delete a specific employee by ID
    path('employees/<int:pk>', EmployeeDetailView.as_view(), name='employee-detail'),
    # Endpoint to update a specific employee by ID
    path('employees/update/<int:pk>', UpdateEmployeeView.as_view(), name='employee-update'),
    # Endpoint to get a list of all employees with only their name and ID
    path('employees/name-id', EmployeeNameIdView.as_view(), name='employee-name-id'),
    # Endpoint to get a list of all users with the role of 'User'
    path('users/only', GetAllRoleUserOnly.as_view(), name='users'),
    
    # Password reset endpoints
    # path('password-reset/request', PasswordResetRequestView.as_view(), name='password_reset_request'),
    # # Endpoint to verify the password reset token
    # path('password-reset/verify', PasswordResetVerifyView.as_view(), name='password_reset_verify'),
    # # Endpoint to reset the password
    # path('password-reset', PasswordResetView.as_view(), name='password_reset'),
]

