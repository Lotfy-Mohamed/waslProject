from django.shortcuts import render

# Create your views here.

from rest_framework import status , permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser , IsAuthenticated , AllowAny 
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.generics import ListAPIView , RetrieveAPIView , CreateAPIView , UpdateAPIView , DestroyAPIView
from .models import ContactUs
from .serializers import ContactUsSerializer


class ListContactUs(ListAPIView):
    queryset = ContactUs.objects.all()
    serializer_class = ContactUsSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

class RetrieveContactUs(RetrieveAPIView):
    queryset = ContactUs.objects.all()
    serializer_class = ContactUsSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]



class CreateContactUs(CreateAPIView):
    querset = ContactUs.objects.all()
    serializer_class = ContactUsSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Contact Us created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UpdateContactUs(UpdateAPIView):
    queryset = ContactUs.objects.all()
    serializer_class = ContactUsSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Contact Us updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class DeleteContactUs(DestroyAPIView):
    queryset = ContactUs.objects.all()
    serializer_class = ContactUsSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]
    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Contact Us deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
