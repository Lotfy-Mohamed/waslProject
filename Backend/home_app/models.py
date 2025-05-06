from django.db import models
from django.urls import reverse

# Create your models here.


class Header(models.Model):
    title = models.CharField(max_length=100)
    sub_description = models.TextField()
    description = models.TextField()

    def __str__(self):
        return self.title


class WhyChooseUs(models.Model):
    title = models.CharField(max_length=100) 
    description = models.TextField(max_length=1000)  
    icon = models.CharField(max_length=100)  
    icons_img = models.ImageField(upload_to='icons_img/', null=True, blank=True)

    def __str__(self):
        return self.title

class Testimonial(models.Model):
    name = models.CharField(max_length=100)
    bussiness_position = models.CharField(max_length=100)
    description = models.TextField(max_length=1000)
    image = models.ImageField(upload_to='testimonial_img/', null=True, blank=True)

    def __str__(self):
        return self.name
    

class SocialMedia(models.Model):
    social_name = models.CharField(max_length=100)
    link = models.URLField(max_length=200)
    icon_social = models.CharField(max_length=100)
    icon_color = models.CharField(max_length=100)

    def __str__(self):
        return self.social_name