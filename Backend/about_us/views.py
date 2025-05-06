from django.shortcuts import render

from .models import AboutUs , AboutUsInfo
from .serializers import AboutUsSerializer , AboutUsInfoSerializer
from rest_framework.permissions import IsAuthenticated , AllowAny , IsAdminUser
from rest_framework.generics import ListAPIView , RetrieveAPIView , UpdateAPIView , DestroyAPIView , CreateAPIView
from rest_framework import status , permissions
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication



class AboutUsList(ListAPIView):
    queryset = AboutUs.objects.all()
    serializer_class = AboutUsSerializer


class AboutUsDetail(RetrieveAPIView):
    queryset = AboutUs.objects.all()
    serializer_class = AboutUsSerializer


class AboutUsUpdate(UpdateAPIView):
    queryset = AboutUs.objects.all()
    serializer_class = AboutUsSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        # Custom message with the data
        response_data = {
            "message": "About Us section updated successfully.",
            "data": serializer.data
        }
        return Response(response_data, status=status.HTTP_200_OK)


class AboutUsCreate (CreateAPIView):
    queryset = AboutUs.objects.all()
    serializer_class = AboutUsSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        # Custom message with the data
        response_data = {
            "message": "About Us section created successfully.",
            "data": serializer.data
        }
        return Response(response_data, status=status.HTTP_201_CREATED)
    

class AboutUsDelete(DestroyAPIView):
    queryset = AboutUs.objects.all()
    serializer_class = AboutUsSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)

        # Custom message with the data
        response_data = {
            "message": "About Us section deleted successfully."
        }
        return Response(response_data, status=status.HTTP_204_NO_CONTENT)

# AboutUsInfoSerializer 

class AboutUsInfoList(ListAPIView):
    queryset = AboutUsInfo.objects.all()
    serializer_class = AboutUsInfoSerializer
    
class AboutUsInfoDetail(RetrieveAPIView):
    queryset = AboutUsInfo.objects.all()
    serializer_class = AboutUsInfoSerializer
    
    
class AboutUsInfoUpdate(UpdateAPIView):
    queryset = AboutUsInfo.objects.all()
    serializer_class = AboutUsInfoSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]
    
class AboutUsInfoCreate (CreateAPIView):
    queryset = AboutUsInfo.objects.all()
    serializer_class = AboutUsInfoSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        # Custom message with the data
        response_data = {
            "message": "About Us Info section created successfully.",
            "data": serializer.data
        }
        return Response(response_data, status=status.HTTP_201_CREATED)
    

class AboutUsInfoDelete(DestroyAPIView):
    queryset = AboutUsInfo.objects.all()
    serializer_class = AboutUsInfoSerializer
    permission_classes = [IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)

        # Custom message with the data
        response_data = {
            "message": "About Us Info section deleted successfully."
        }
        return Response(response_data, status=status.HTTP_204_NO_CONTENT)