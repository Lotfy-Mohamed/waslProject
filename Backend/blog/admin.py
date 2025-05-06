from django.contrib import admin

# Register your models here.

from .models import Blog, Category


class BlogAdmin(admin.ModelAdmin):
    list_display = ('id','title', 'author','author_name' ,  'category', 'created_at')


class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')

admin.site.register(Blog, BlogAdmin)
admin.site.register(Category , CategoryAdmin)