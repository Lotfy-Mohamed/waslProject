from django.contrib import admin

from .models import ContactUs


class ContactUsAdmin(admin.ModelAdmin):
    list_display = ('id','name', "email",'created_at')
    search_fields = ('name', 'email', 'message')


admin.site.register(ContactUs, ContactUsAdmin)
