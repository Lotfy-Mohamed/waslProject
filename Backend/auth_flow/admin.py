from django.contrib import admin

# Register your models here.

from .models import AllUsers , Employee , PasswordResetOTP

class AllUsersAdmin(admin.ModelAdmin):
    list_display = ('first_name', 'id','username', 'role', 'date_joined' , 'is_staff' , 'is_active' , 'is_superuser')

admin.site.register(AllUsers, AllUsersAdmin)


class EmployeeAdmin(admin.ModelAdmin):
    list_display = ('get_first_name', 'id', 'get_email', 'get_phone', 'get_role', 'position', 'company_name' , 'username')

    # Methods to access related fields from the AllUsers model
    def get_first_name(self, obj):
        return obj.user.first_name
    get_first_name.short_description = 'First Name'

    def get_email(self, obj):
        return obj.user.email
    get_email.short_description = 'Email'

    def get_phone(self, obj):
        return obj.user.phone
    get_phone.short_description = 'Phone'

    def get_role(self, obj):
        return obj.user.role
    get_role.short_description = 'Role'
    
    def username(self, obj):
        return obj.user.username
    
admin.site.register(Employee, EmployeeAdmin)


class PasswordResetOTPAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'otp', 'created_at')
    
    
admin.site.register(PasswordResetOTP, PasswordResetOTPAdmin)