from rest_framework import serializers
from .models import Blog, Category

# Serializer for Category
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']

# Serializer for Blog
class BlogSerializer(serializers.ModelSerializer):
    
    category = CategorySerializer()  # Nested category information

    class Meta:
        model = Blog
        fields = '__all__'


class BlogSearchSerializerCreateUpdate(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = '__all__'
