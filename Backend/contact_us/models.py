from django.db import models

# Create your models here.

class ContactUs(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    name = models.CharField(max_length=200, blank=True, null=True)  # Full name field
    email = models.EmailField() 
    phone_number = models.CharField(max_length=15)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Combine first and last names to create the full name
        self.name = f'{self.first_name} {self.last_name}'
        super(ContactUs, self).save(*args, **kwargs)

    def __str__(self):
        return self.name
