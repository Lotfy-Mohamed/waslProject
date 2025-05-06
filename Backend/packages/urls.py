from django.urls import path
from .views import PackageViewSet, PackageOrderViewSet , PackageByIdViewSet , PackageUpdateViewSet , CreatePackage , DeletePackage , GetAllOrders

urlpatterns = [
    # Endpoint to get all packages
    path('', PackageViewSet.as_view({'get': 'list'}), name='packages'),

    # Endpoint to create a package order
    path('package-orders', PackageOrderViewSet.as_view({'post': 'create'}), name='create-package-order'),

    # Endpoint to get all orders for the logged-in user
    path('package-orders/my-orders', PackageOrderViewSet.as_view({'get': 'my_orders'}), name='my-orders'),

    # Endpoint to get a single package by ID
    path('id/<int:pk>', PackageByIdViewSet.as_view(), name='package-by-id'),

    # Endpoint to update a single package by ID
    path('update/<int:pk>', PackageUpdateViewSet.as_view(), name='update-package'),

    # Endpoint to create a new package
    path('create', CreatePackage.as_view(), name='create-package'),

    # Endpoint to delete a single package by ID
    path('delete/<int:pk>', DeletePackage.as_view(), name='delete-package'),
    
    # Endpoint to get all orders
    path('orders', GetAllOrders.as_view(), name='all-orders'),
]
