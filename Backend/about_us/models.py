from django.db import models

# Create your models here.

class AboutUs(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    sub_description = models.TextField(null=True, blank=True)
    items = models.JSONField(null=True, default=list)
    image = models.ImageField(upload_to='about_us/' , null=True, blank=True)

    def __str__(self):
        return self.title
    
    
    
    
class AboutUsInfo(models.Model):
    phone_number = models.CharField(max_length=15)
    email = models.EmailField()
    
    def __str__(self):
        return self.email
    
    # def save(self, *args, **kwargs):
        # # Ensure that only one record exists
        # if not self.pk and AboutUsInfo.objects.exists():
        #     raise ValueError("Only one AboutUsInfo instance is allowed.")
        # super(AboutUsInfo, self).save(*args, **kwargs)