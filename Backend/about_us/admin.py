from django.contrib import admin

# Register your models here.

from .models import AboutUs , AboutUsInfo

class AboutUsAdmin(admin.ModelAdmin):
    list_display = ('id','title' , 'image')


admin.site.register(AboutUs, AboutUsAdmin)


class AboutUsInfoAdmin(admin.ModelAdmin):
    list_display = ('id','phone_number' , 'email')

admin.site.register(AboutUsInfo , AboutUsInfoAdmin)
