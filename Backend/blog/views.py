from rest_framework.generics import ListAPIView, RetrieveAPIView, CreateAPIView, UpdateAPIView, DestroyAPIView
from .models import Blog, Category
from .serializers import BlogSerializer, CategorySerializer , BlogSearchSerializerCreateUpdate

from rest_framework.permissions import IsAuthenticated , IsAdminUser , AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication

from rest_framework import filters
from django_filters import rest_framework as django_filters
import django_filters
from rest_framework.exceptions import NotFound
from rest_framework.response import Response
from rest_framework import status


# List all blogs
class BlogListView(ListAPIView):
    """
    API endpoint to retrieve all blogs.
    """
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer

# Retrieve a single blog by ID
class BlogRetrieveView(RetrieveAPIView):
    """
    API endpoint to retrieve a single blog by its ID.
    """
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer

# Create a new blog
class BlogCreateView(CreateAPIView):
    """
    API endpoint to create a new blog.
    """
    queryset = Blog.objects.all()
    serializer_class = BlogSearchSerializerCreateUpdate
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

# Update an existing blog
class BlogUpdateView(UpdateAPIView):
    """
    API endpoint to update an existing blog.
    """
    queryset = Blog.objects.all()
    serializer_class = BlogSearchSerializerCreateUpdate
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

# Delete a blog
class BlogDeleteView(DestroyAPIView):
    """
    API endpoint to delete a blog.
    """
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"detail": "Blog deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )

# List blogs by category
class BlogsByCategoryView(ListAPIView):
    """
    API endpoint to retrieve blogs filtered by a specific category.
    """
    serializer_class = BlogSerializer

    def get_queryset(self):
        category_id = self.kwargs['category_id']
        return Blog.objects.filter(category_id=category_id)
    

# Blog filter class
# class BlogFilter(django_filters.FilterSet):
#     search = django_filters.CharFilter(field_name='title', lookup_expr='icontains', label='Search Title')
    
#     class Meta:
#         model = Blog
#         fields = ['search']

# # Blog List View with Search
# class BlogSearchView(ListAPIView):
#     queryset = Blog.objects.all()
#     serializer_class = BlogSerializer
#     filter_backends = (filters.OrderingFilter, filters.SearchFilter, django_filters.rest_framework.DjangoFilterBackend)
#     filterset_class = BlogFilter
#     search_fields = ['title', 'sub_description', 'content']  # Fields you want to allow search on
#     ordering_fields = ['created_at']  # You can add other fields you want to allow sorting by
#     ordering = ['created_at']  # Default ordering by creation date


class BlogSearchView(ListAPIView):
    serializer_class = BlogSerializer

    def get_queryset(self):
        query = self.request.query_params.get('search', '')
        return Blog.objects.filter(title__icontains=query)

# List all categories
class CategoryListView(ListAPIView):
    """
    API endpoint to retrieve all categories.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

# Retrieve a single category by ID
class CategoryRetrieveView(RetrieveAPIView):
    """
    API endpoint to retrieve a single category by its ID.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

# Create a new category
class CategoryCreateView(CreateAPIView):
    """
    API endpoint to create a new category.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

# Update an existing category
class CategoryUpdateView(UpdateAPIView):
    """
    API endpoint to update an existing category.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]


# Delete a category
class CategoryDeleteView(DestroyAPIView):
    """
    API endpoint to delete a category.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def delete(self, request, *args, **kwargs):
        try:
            # Get the category object to be deleted
            category = self.get_object()

            # Perform the deletion
            category.delete()

            # Return success response
            return Response(
                {"detail": "Category deleted successfully."},
                status=status.HTTP_204_NO_CONTENT
            )
        
        except Category.DoesNotExist:
            raise NotFound(detail="Category not found.")


