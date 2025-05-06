from django.shortcuts import render

# Create your views here.
from rest_framework import status, generics
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from .models import Service , ServiceOrder , ServiceStep, ServiceOrderStep
from .serializers import (
    ServiceSerializer , ServiceOrderSerializer,
    CreateOrderSerializer , UpdateOrderSerializer , 
    ServiceOrderStepSerializer , ServiceForHomeSerializer,
    ServiceForSinglePageByIdSerializer , AllserviceNameIDOnlySerializer ,ServiceImageSerializer
)

from rest_framework.response import Response 
from rest_framework import status
from rest_framework.views import APIView
from auth_flow.models import Employee , AllUsers as User , Employee
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import NotFound


# Home Page Views
class ServiceForHomeView(generics.ListAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceForHomeSerializer

class ServiceForSinglePageByIdView(generics.RetrieveAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceForSinglePageByIdSerializer
    
    
class AllserviceNameIDOnlyView(generics.ListAPIView):
    queryset = Service.objects.all()
    serializer_class = AllserviceNameIDOnlySerializer

# Admin Views for Services
class ServiceCreateView(generics.CreateAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

class ServiceListView(generics.ListAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

class ServiceAddImageView(generics.UpdateAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceImageSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

class ServiceDetailView(generics.RetrieveAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

class ServiceUpdateView(generics.UpdateAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

class ServiceDeleteView(generics.DestroyAPIView):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()

        message = {
            "message": "Service deleted successfully"
        }
        
        return Response(status=status.HTTP_204_NO_CONTENT , data=message)



# Handlr Order Views

# List all orders (Admin only)


class ServiceOrderListView(generics.ListAPIView):
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        If the user is an admin, return all orders.
        Otherwise, return orders for the authenticated user.
        """
        if self.request.user.is_staff:  # Check if the user is an admin
            orders = ServiceOrder.objects.all()
            if orders.count() == 0:  # If no orders are found, return a 404 response
                raise NotFound("No orders found")
            return orders
        # If the user is not an admin, return orders related to the authenticated user
        return ServiceOrder.objects.filter(user=self.request.user)

    def list(self, request, *args, **kwargs):
        """
        Custom list method to handle returning data.
        This method ensures we handle both 404 cases and normal responses properly.
        """
        queryset = self.get_queryset()
        if queryset.count() == 0:
            return Response({"error": "No orders found"}, status=404)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

# Get All Orders Employee Has
class ServiceOrderListViewEmployee(generics.ListAPIView):
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        If the user is an admin, return all orders.
        Otherwise, return orders for the authenticated user.
        """
        employee = Employee.objects.get(user=self.request.user)
        orders = ServiceOrder.objects.filter(assigned_employee=employee)
        if orders.count() == 0:  # If no orders are found, return a 404 response
            raise NotFound("No orders found")
        return orders

    def list(self, request, *args, **kwargs):
        """
        Custom list method to handle returning data.
        This method ensures we handle both 404 cases and normal responses properly.
        """
        queryset = self.get_queryset()
        if queryset.count() == 0:
            return Response({"error": "No orders found"}, status=404)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# Retrieve a single order (Admin and User who created it)
class ServiceOrderDetailView(generics.RetrieveAPIView):
    queryset = ServiceOrder.objects.all()
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """
        Retrieve the order by checking if the user is an admin or the creator.
        """
        obj = super().get_object()
        if obj.user != self.request.user and not self.request.user.is_staff:
            raise NotFound("You do not have permission to access this order.")
        return obj


# Create a new order
class ServiceOrderCreateView(generics.CreateAPIView):
    queryset = ServiceOrder.objects.all()
    serializer_class = CreateOrderSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    
    def perform_create(self, serializer):
        service = serializer.validated_data['service']
        user = self.request.user
        order = serializer.save(user=user)

        # Add all steps of the service to the order
        service_steps = ServiceStep.objects.filter(service=service)
        for step in service_steps:
            ServiceOrderStep.objects.create(
                order=order,
                step=step,
                status='pending',  # Default status
                payment_status='unpaid',  # Default payment status
                step_price=step.step_price,
                name=step.name,
                step_description = step.step_description,
                requirements_data_from_user = step.requirements_data_from_user,
                files = step.files,
                data_req_user = step.data_req_user,
                data_user_file_upload = step.data_user_file_upload,
                step_result_text = step.step_result_text,
                step_result_file = step.step_result_file
            )


# Create a new order for admin
class CreatOrderForAdminView(generics.CreateAPIView):
    queryset = ServiceOrder.objects.all()
    serializer_class = CreateOrderSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def create(self, request, *args, **kwargs):
        """
        Override the create method to handle `userid` from the request body.
        """
        user_id = request.data.get('userid')
        if not user_id:
            return Response(
                {"error": "User ID is required in the request body."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": f"User with ID {user_id} does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Process the service
        service_id = request.data.get('service')
        if not service_id:
            return Response(
                {"error": "Service ID is required in the request body."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            service = Service.objects.get(id=service_id)
        except Service.DoesNotExist:
            return Response(
                {"error": f"Service with ID {service_id} does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Prepare data for serializer
        data = request.data.copy()
        data['user'] = user.id  # Inject user ID into the data
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        order = serializer.save(user=user, service=service)

        # Add all steps of the service to the order
        service_steps = ServiceStep.objects.filter(service=service)
        for step in service_steps:
            ServiceOrderStep.objects.create(
                order=order,
                step=step,
                status='pending',  # Default status
                payment_status='unpaid',  # Default payment status
                step_price=step.step_price,
                name=step.name,
                step_description = step.step_description,
                requirements_data_from_user = step.requirements_data_from_user,
                files = step.files,
            )

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)



# Delete an order
class ServiceOrderDeleteView(generics.DestroyAPIView):
    queryset = ServiceOrder.objects.all()
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def destroy(self, request, *args, **kwargs):
        """
        Override the destroy method to handle permission checking and custom response.
        """
        obj = self.get_object()
        if obj.user != request.user and not request.user.is_staff:
            raise NotFound("You do not have permission to delete this order.")
        
        # Perform the delete operation
        self.perform_destroy(obj)

        # Return a custom response message
        return Response({"message": "Order deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

# Update an order
class ServiceOrderUpdateView(generics.UpdateAPIView):
    queryset = ServiceOrder.objects.all()
    serializer_class = UpdateOrderSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_object(self):
        """
        Retrieve the order only if the user is admin or the creator.
        """
        obj = super().get_object()
        if obj.user != self.request.user and not self.request.user.is_staff:
            raise NotFound("You do not have permission to update this order.")
        return obj


# Assign order to employee (Admin only)
class AssignOrderToEmployeeView(generics.UpdateAPIView):
    queryset = ServiceOrder.objects.all()
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        """
        Assign the order to a specific employee (admin only).
        """
        order = self.get_object()
        employee_id = request.data.get('employee_id')
        try:
            employee = Employee.objects.get(id=employee_id)
        except Employee.DoesNotExist:
            return Response({"error": "Employee not found"}, status=404)

        if not request.user.is_staff:
            return Response({"error": "You do not have permission to assign an employee to this order."}, status=403)

        order.assigned_employee = employee
        order.save()
        return Response(self.get_serializer(order).data)



class UserServiceOrderListView(generics.ListAPIView):
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Return all orders for the logged-in user.
        """
        return ServiceOrder.objects.filter(user=self.request.user)

    def list(self, request, *args, **kwargs):
        """
        Override the list method to handle empty results.
        """
        queryset = self.get_queryset()

        if not queryset.exists():
            return Response({"message": "You do not have any orders yet."}, status=404)
        
        # Return the list of orders with the serialized data
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)




# class UpdateOrderStepStatusView(generics.UpdateAPIView):
#     queryset = ServiceOrderStep.objects.all()
#     serializer_class = ServiceOrderStepSerializer
#     permission_classes = [IsAuthenticated]
#     authentication_classes = [JWTAuthentication]

#     def update(self, request, *args, **kwargs):
#         step = self.get_object()
#         order = step.order
#         getOrder = ServiceOrder.objects.get(id=order.id)

#         get_Employee = Employee.objects.get(user=self.request.user)
        
#         print(get_Employee , "Employee")
        
#         # print(getOrder.assigned_employee.username , "assigned employee")
#         if get_Employee != self.request.user:
#             # print(step.order.assigned_employee.username)
#             print(self.request.user , "User Name logged in")
#             return Response({"detail": "You do not have permission to modify this step."}, status=status.HTTP_403_FORBIDDEN)
#         return super().update(request, *args, **kwargs)


class UpdateOrderStepStatusView(generics.UpdateAPIView):
    queryset = ServiceOrderStep.objects.all()
    serializer_class = ServiceOrderStepSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        step = self.get_object()
        if step.order.user != self.request.user:
            return Response({"detail": "You do not have permission to modify this step."}, status=status.HTTP_403_FORBIDDEN)
        return super().update(request, *args, **kwargs)


class UpdateOrderStepStatusViewManagerAdmin(generics.UpdateAPIView):
    queryset = ServiceOrderStep.objects.all()
    serializer_class = ServiceOrderStepSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        step = self.get_object()
        if self.request.user.role == "Manager" or self.request.user.role == "Admin":
            return super().update(request, *args, **kwargs)
        return Response({"detail": "You do not have permission to modify this step."}, status=status.HTTP_403_FORBIDDEN)


# class UpdateOrderStepStatusViewManagerAdmin(generics.UpdateAPIView):
#     queryset = ServiceOrderStep.objects.all()
#     serializer_class = ServiceOrderStepSerializer
#     permission_classes = [IsAuthenticated]

#     def update(self, request, *args, **kwargs):
#         step = self.get_object()
#         if step.order.assigned_employee.user.role == "Manager" or self.request.user.role == "Admin":
#             print(f"{self.request.user.role} is an Admin or Manager.")
#             return super().update(request, *args, **kwargs)
#         print(f"{self.request.user} is not an Admin or Manager.")
#         return Response({"detail": "You do not have permission to modify this step."}, status=status.HTTP_403_FORBIDDEN)



# class UpdateOrderStepStatusViewManagerAdmin(generics.UpdateAPIView):
#     queryset = ServiceOrderStep.objects.all()
#     serializer_class = ServiceOrderStepSerializer
#     permission_classes = [IsAuthenticated]

#     def update(self, request, *args, **kwargs):
#         step = self.get_object()
#         user_role = str(self.request.user.role).strip().lower()

#         # Check if the user is 'admin' or 'manager' and handle accordingly
#         if user_role in ["manager", "admin"]:
#             # Execute code specifically for Admin or Manager
#             print(f"{self.request.user} is an Admin or Manager.")
#             return super().update(request, *args, **kwargs)
#             # Deny access to modify the step
#         # Proceed with the default update action for non-Admin/Manager roles
#         return Response({"detail": "You do not have permission to modify this step."}, status=status.HTTP_403_FORBIDDEN)






        # if step.order.assigned_employee.user.role == "Manager" or self.request.user.role == "Admin":