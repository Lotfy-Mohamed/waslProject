from django.shortcuts import render

# Create your views here.


from rest_framework.permissions import IsAuthenticated , AllowAny , IsAdminUser
from rest_framework import status ,viewsets, permissions
from rest_framework.response import Response
from rest_framework.generics import ListAPIView, RetrieveAPIView, CreateAPIView, DestroyAPIView, UpdateAPIView 
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Package, PackageOrder
from .serializers import PackageSerializer, PackageOrderSerializer , GetAllOrdersSerializer
from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet




class PackageViewSet(ModelViewSet):
    """
    Handles listing all packages.
    """
    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]  # Anyone can view packages


class PackageByIdViewSet(RetrieveAPIView):
    """
    Handles retrieving a single package by ID.
    """
    queryset = Package.objects.all()
    serializer_class = PackageSerializer


class PackageUpdateViewSet(UpdateAPIView):
    """
    Handles updating a single package by ID.
    """
    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]


class CreatePackage(CreateAPIView):
    """
    Handles creating a new package.
    """
    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]


class DeletePackage(DestroyAPIView):
    """
    Handles deleting a single package by ID.
    """
    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def delete(self, request, *args, **kwargs):
        """
        Override the delete method to return a custom response.
        """
        instance = self.get_object()

        # Check if the package is related to any orders
        related_orders = PackageOrder.objects.filter(package=instance)

        if related_orders.exists():
            return Response(
                {"message": "Cannot delete this package, it is related to existing orders."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Proceed with the deletion if no orders are related
        self.perform_destroy(instance)
        return Response(
            {"message": "Package deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )

class PackageOrderViewSet(ModelViewSet):
    """
    Handles creating and listing package orders.
    """
    queryset = PackageOrder.objects.all()
    serializer_class = PackageOrderSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]  # Allow both authenticated and unauthenticated users

    def perform_create(self, serializer):
        """
        Customize creation behavior based on whether the user is authenticated.
        """
        user = self.request.user
        if user.is_authenticated:
            serializer.save(user=user, name=user.username, email=user.email)
        else:
            serializer.save()
            
    @action(detail=False, methods=['get'], url_path='my-orders', url_name='my-orders')
    def my_orders(self, request):
        """
        Retrieve all orders for the logged-in user.
        """
        user = request.user
        orders = PackageOrder.objects.filter(user=user)
        serializer = PackageOrderSerializer(orders, many=True)
        return Response(serializer.data)


class GetAllOrders(ListAPIView):
    """
    Handles listing all orders.
    """
    queryset = PackageOrder.objects.all()
    serializer_class = GetAllOrdersSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]  # Only admin users can view all orders