from django.db import models

from auth_flow.models import AllUsers as User

# Category Model
class Category(models.Model):
    name = models.CharField(max_length=255)  # Category name

    def __str__(self):
        return self.name

# Blog Model
class Blog(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blogs' , null=True , blank=True)  # Related author
    author_name = models.CharField(max_length=255)  # Author name
    author_image = models.ImageField(upload_to='author_images/' , null=True , blank=True)  # Author image
    author_position = models.CharField(max_length=255)  # Author position
    title = models.CharField(max_length=255)  # Blog title
    sub_description = models.CharField(max_length=255)  # Blog sub description
    content = models.TextField()  # Blog content
    quote = models.CharField(max_length=255)  # Blog quote
    image = models.ImageField(upload_to='blog_images/' , null=True , blank=True)  # Blog image
    answer_question = models.JSONField(default=list)  # Blog answer question {"question" : value , "answer" : value}
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='blogs')  # Related category
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for blog creation

    def __str__(self):
        return self.title