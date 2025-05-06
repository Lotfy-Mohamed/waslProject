from django.urls import path
from .views import (
    ServiceCreateView,
    ServiceListView,
    ServiceDetailView,
    ServiceUpdateView,
    ServiceDeleteView,
    ServiceOrderListView,
    ServiceOrderDetailView,
    ServiceOrderCreateView,
    ServiceOrderUpdateView,
    ServiceOrderDeleteView,
    AssignOrderToEmployeeView,
    UserServiceOrderListView,
    CreatOrderForAdminView,
    UpdateOrderStepStatusView,
    UpdateOrderStepStatusViewManagerAdmin,
    ServiceForHomeView,
    ServiceForSinglePageByIdView,
    AllserviceNameIDOnlyView,
    ServiceAddImageView,
    ServiceOrderListViewEmployee
)

urlpatterns = [
    # Home
    path('home', ServiceForHomeView.as_view(), name='service-home'), # List all services
    path('page/<int:pk>', ServiceForSinglePageByIdView.as_view(), name='service-detail'), # Retrieve a single service
    path('all/name-id', AllserviceNameIDOnlyView.as_view(), name='service-list'), # List all services
    # Services
    path('create', ServiceCreateView.as_view(), name='service-create'), # Create a service
    path('', ServiceListView.as_view(), name='service-list'), # List all services
    path('<int:pk>', ServiceDetailView.as_view(), name='service-detail'), # Retrieve a single service
    path('update/<int:pk>', ServiceUpdateView.as_view(), name='service-update'), # Update a service
    path('<int:pk>/delete', ServiceDeleteView.as_view(), name='service-delete'), # Delete a service
    path('add-image/<int:pk>', ServiceAddImageView.as_view(), name='service-add-image'), # Add an image to a service
    # Orders
    path('orders', ServiceOrderListView.as_view(), name='order-list'), # List all orders
    path('orders/<int:pk>', ServiceOrderDetailView.as_view(), name='order-detail'), # Retrieve a single order
    path('orders/create', ServiceOrderCreateView.as_view(), name='order-create'), # Create an order
    path('orders/create/spacific-user', CreatOrderForAdminView.as_view(), name='order-create'), # Create an order for a specific user
    path('orders/delete/<int:pk>', ServiceOrderDeleteView.as_view(), name='order-delete'),  # Delete an order
    path('orders/update/<int:pk>', ServiceOrderUpdateView.as_view(), name='order-update'), # Update an order
    path('orders/assign-employee/<int:pk>', AssignOrderToEmployeeView.as_view(), name='order-assign-employee'), # Assign order to employee
    path('orders/my-orders', UserServiceOrderListView.as_view(), name='user-order-list'), # List all orders of the logged-in user
    path('orders/steps/<int:pk>/update', UpdateOrderStepStatusView.as_view(), name='update-step-status'), # Step ID to update the status of the step
    path('orders/steps/<int:pk>/update/manager-admin', UpdateOrderStepStatusViewManagerAdmin.as_view(), name='update-step-status-manager-admin'), # Step ID to update the status of the step
    path('orders/employee-orders', ServiceOrderListViewEmployee.as_view(), name='employee-order-list'), # List all orders of the logged-in employee
]

