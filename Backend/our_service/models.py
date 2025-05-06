from django.db import models
from auth_flow.models import AllUsers as User , Employee

STATUS_CHOICES_Step = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('in_progress', 'In Progress'),  
]

Service_Status = [
    ('Completed', 'Completed'),
    ('In Progress', 'In Progress'),
    ('Rejected', 'Rejected'),
]

# Service Model
class Service(models.Model):
    name = models.CharField(max_length=255)
    sub_description = models.TextField()
    description = models.TextField()
    icon_service = models.CharField(max_length=255, null=True, blank=True)
    image_service = models.ImageField(upload_to="service_images/", null=True, blank=True)
    benifits_service = models.JSONField(null=True, blank=True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=255, choices=Service_Status, default="In Progress")
    def __str__(self):
        return self.name

payment_status = [
    ('unpaid', 'Unpaid'),
    ('in_progress', 'In Progress'),
    ('paid', 'Paid'),
]

# Service Step Model
class ServiceStep(models.Model):
    service = models.ForeignKey(Service, related_name="steps", on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    step_description = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=255, choices=STATUS_CHOICES_Step, default="pending")
    requirements_data_from_user = models.TextField(null=True, blank=True)
    files = models.FileField(upload_to="service_steps/", null=True, blank=True)
    data_req_user = models.TextField(null=True, blank=True)
    data_user_file_upload = models.FileField(upload_to="service_steps/", null=True, blank=True)
    step_price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00 , null=True, blank=True)
    payment_status = models.CharField(max_length=255, choices=payment_status, default="unpaid" , null=True, blank=True)
    step_result_text = models.TextField(null=True, blank=True)
    step_result_file = models.FileField(upload_to="service_steps/", null=True, blank=True)

    def __str__(self):
        return f"Step {self.name} of {self.service.name}"


Order_Status = [
    ('new', 'New'),
    ('in_progress', 'In Progress'),
    ('completed', 'Completed'),
]

# Order Model
class ServiceOrder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    service = models.ForeignKey(Service, on_delete=models.CASCADE)
    status = models.CharField(max_length=255, choices=Order_Status, default="new", null=True, blank=True)
    assigned_employee = models.ForeignKey(Employee, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order #{self.id} for {self.user.username}"
    
    
    
# Order Step Model
class ServiceOrderStep(models.Model):
    order = models.ForeignKey(ServiceOrder, related_name="steps", on_delete=models.CASCADE)
    step = models.ForeignKey(ServiceStep, on_delete=models.CASCADE)
    status = models.CharField(max_length=255, choices=STATUS_CHOICES_Step, default="pending" , null=True, blank=True)
    payment_status = models.CharField(max_length=255, choices=payment_status, default="unpaid" , null=True, blank=True)
    step_price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00 , null=True, blank=True)
    name = models.CharField(max_length=255, default="")
    step_description = models.TextField(default="" , null=True, blank=True)
    requirements_data_from_user = models.TextField(null=True, blank=True)
    files = models.FileField(upload_to="service_steps/", null=True, blank=True)
    data_req_user = models.TextField(null=True, blank=True)
    data_user_file_upload = models.FileField(upload_to="service_steps/", null=True, blank=True)
    step_result_text = models.TextField(null=True, blank=True)
    step_result_file = models.FileField(upload_to="service_steps/", null=True, blank=True)

    def __str__(self):
        return f"Step {self.step.name} for Order #{self.order.id}"