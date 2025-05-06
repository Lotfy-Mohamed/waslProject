from django.contrib import admin

# Register your models here.

from .models import Header , WhyChooseUs , Testimonial , SocialMedia


class HeaderAdmin(admin.ModelAdmin):
    list_display = ['id' ,'title', 'sub_description']

admin.site.register(Header, HeaderAdmin)

class WhyChooseUsAdmin(admin.ModelAdmin):
    list_display = ['id' ,'title']

admin.site.register(WhyChooseUs, WhyChooseUsAdmin)


class TestimonialAdmin(admin.ModelAdmin):
    list_display = ['id' ,'name'  , 'bussiness_position']


admin.site.register(Testimonial, TestimonialAdmin)


class SocialMediaAdmin(admin.ModelAdmin):
    list_display = ['id' , 'social_name' , 'icon_social']

admin.site.register(SocialMedia, SocialMediaAdmin)