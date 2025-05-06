
from django.urls import path



from .views import AboutUsList , AboutUsDetail , AboutUsUpdate , AboutUsCreate , AboutUsDelete
from .views import AboutUsInfoList , AboutUsInfoDetail , AboutUsInfoUpdate , AboutUsInfoCreate , AboutUsInfoDelete



urlpatterns = [
    path('', AboutUsList.as_view() , name='about_us_list'),
    path('detail/<int:pk>/', AboutUsDetail.as_view() , name='about_us_detail'),
    path('update/<int:pk>', AboutUsUpdate.as_view() , name='about_us_update'),
    path('create', AboutUsCreate.as_view() , name='about_us_create'),
    path('delete/<int:pk>', AboutUsDelete.as_view() , name='about_us_delete'),
    # AboutUsInfo
    path('info', AboutUsInfoList.as_view() , name='about_us_info_list'),
    path('info/detail/<int:pk>', AboutUsInfoDetail.as_view() , name='about_us_info_detail'),
    path('info/update/<int:pk>', AboutUsInfoUpdate.as_view() , name='about_us_info_update'),
    path('info/create', AboutUsInfoCreate.as_view() , name='about_us_info_create'),
    path('info/delete/<int:pk>', AboutUsInfoDelete.as_view() , name='about_us_info_delete'),
]