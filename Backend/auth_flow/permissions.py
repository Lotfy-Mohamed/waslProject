from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admins to update user roles.
    """
    def has_permission(self, request, view):
        # Check if the user is an admin
        return request.user and request.user.is_superuser
