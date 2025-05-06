from django.db import models
# from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from auth_flow.models import AllUsers as User



class Package(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    duration_in_days = models.CharField(max_length=100)
    benefits = models.JSONField(null=True, default=list)
    
    def __str__(self):
        return self.name

class PackageOrder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    package = models.ForeignKey(Package, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, blank=True)
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=15, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    id_package = models.CharField(max_length=100, blank=True)

    def clean(self):
        if not self.user and (not self.name or not self.email or not self.phone):
            raise ValidationError("Name, email, and phone must be provided if user is not logged in.")

    def save(self, *args, **kwargs):

        ## get the id of the package
        self.id_package = self.package.id
        if self.user:
            self.name = self.user.get_full_name() or self.user.username
            self.email = self.user.email
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Order by {self.name} for {self.package.name}"
