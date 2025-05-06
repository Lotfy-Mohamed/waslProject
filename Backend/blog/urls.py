from django.urls import path
from .views import (
    BlogListView, BlogRetrieveView, BlogCreateView, BlogUpdateView, BlogDeleteView, BlogsByCategoryView, BlogSearchView,
    CategoryListView, CategoryRetrieveView, CategoryCreateView, CategoryUpdateView, CategoryDeleteView
)

urlpatterns = [
    # Blog URLs
    path('', BlogListView.as_view(), name='blog-list'),
    path('<int:pk>', BlogRetrieveView.as_view(), name='blog-detail'),
    path('create', BlogCreateView.as_view(), name='blog-create'),
    path('update/<int:pk>', BlogUpdateView.as_view(), name='blog-update'),
    path('delete/<int:pk>', BlogDeleteView.as_view(), name='blog-delete'),
    path('category/<int:category_id>', BlogsByCategoryView.as_view(), name='blogs-by-category'),
    path('search', BlogSearchView.as_view(), name='blog-list-search'),

    # Category URLs
    path('categories', CategoryListView.as_view(), name='category-list'),
    path('categories/<int:pk>', CategoryRetrieveView.as_view(), name='category-detail'),
    path('categories/create', CategoryCreateView.as_view(), name='category-create'),
    path('categories/update/<int:pk>', CategoryUpdateView.as_view(), name='category-update'),
    path('categories/delete/<int:pk>', CategoryDeleteView.as_view(), name='category-delete'),
]
