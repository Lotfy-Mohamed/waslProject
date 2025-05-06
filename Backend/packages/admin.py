from django.contrib import admin

# Register your models here.

from .models import Package, PackageOrder

class PackageAdmin(admin.ModelAdmin):
    list_display = ('id','name', 'price', 'duration_in_days')


class PackageOrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'email', 'phone', 'created_at')

admin.site.register(Package, PackageAdmin)
admin.site.register(PackageOrder, PackageOrderAdmin)