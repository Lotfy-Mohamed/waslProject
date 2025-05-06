
from django.urls import path , include

from .views import ListContactUs , RetrieveContactUs ,CreateContactUs ,UpdateContactUs ,DeleteContactUs



urlpatterns = [
    path('', ListContactUs.as_view() , name='list_contact_us'),
    path('id/<int:pk>', RetrieveContactUs.as_view() , name='retrieve_contact_us'),
    path('create', CreateContactUs.as_view() , name='create_contact_us'),
    path('update/<int:pk>', UpdateContactUs.as_view() , name='update_contact_us'),
    path('delete/<int:pk>', DeleteContactUs.as_view() , name='delete_contact_us'),

]