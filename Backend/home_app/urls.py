from django.urls import path , include

from .views import HeaderListCreateView  , HeaderGetByIdView , WhyChooseUsListCreateView , WhyChooseUsGetByIdView , WhyChooseUsUpdateDestroyView

from .views import TestimonialListView , TestimonialGetByIdView , TestimonialCreateView , TestimonialUpdateView , TestimonialDeleteView

from .views import SocialMediaListView , SocialMediaGetByIdView , SocialMediaCreateView , SocialMediaUpdateView , SocialMediaDeleteView

urlpatterns = [
    path('header', HeaderListCreateView.as_view(), name='header-list-create'),
    path('header/<int:pk>', HeaderGetByIdView.as_view(), name='header-get-by-id'),
    path('why-choose-us', WhyChooseUsListCreateView.as_view(), name='why-choose-us-list-create'),
    path('why-choose-us/<int:pk>', WhyChooseUsGetByIdView.as_view(), name='why-choose-us-get-by-id'),
    path('why-choose-us/<int:pk>/update', WhyChooseUsUpdateDestroyView.as_view(), name='why-choose-us-update-destroy'),
    path('why-choose-us/<int:pk>/delete', WhyChooseUsUpdateDestroyView.as_view(), name='why-choose-us-update-destroy'),
    path('testimonial', TestimonialListView.as_view(), name='testimonial-list'),
    path('testimonial/<int:pk>', TestimonialGetByIdView.as_view(), name='testimonial-get-by-id'),
    path('testimonial/create', TestimonialCreateView.as_view(), name='testimonial-create'),
    path('testimonial/<int:pk>/update', TestimonialUpdateView.as_view(), name='testimonial-update'),
    path('testimonial/<int:pk>/delete', TestimonialDeleteView.as_view(), name='testimonial-delete'),
    path('social-media', SocialMediaListView.as_view(), name='social-media-list'),
    path('social-media/<int:pk>', SocialMediaGetByIdView.as_view(), name='social-media-get-by-id'),
    path('social-media/create', SocialMediaCreateView.as_view(), name='social-media-create'),
    path('social-media/<int:pk>/update', SocialMediaUpdateView.as_view(), name='social-media-update'),
    path('social-media/<int:pk>/delete', SocialMediaDeleteView.as_view(), name='social-media-delete'),
]