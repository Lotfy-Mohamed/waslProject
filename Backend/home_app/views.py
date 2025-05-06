from django.shortcuts import render

# Create your views here.

from .serializers import HeaderSerializer , WhyChooseUsSerializer , TestimonialSerializer , SocialMediaSerializer
from rest_framework.generics import ListCreateAPIView , RetrieveUpdateDestroyAPIView, ListAPIView , RetrieveAPIView , CreateAPIView , UpdateAPIView , DestroyAPIView
from rest_framework import permissions , status
from rest_framework.response import Response
from .models import Header , WhyChooseUs , Testimonial , SocialMedia
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated, DjangoModelPermissions , IsAdminUser , AllowAny
from rest_framework.decorators import authentication_classes, permission_classes


# Header Section

class HeaderListCreateView(ListCreateAPIView):
    queryset = Header.objects.all()
    serializer_class = HeaderSerializer

    def list(self, request, *args, **kwargs):
        # List without specific authentication or permissions
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {"message": "Headers retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )

    @authentication_classes([JWTAuthentication])
    @permission_classes([permissions.IsAuthenticated, permissions.IsAdminUser])
    def create(self, request, *args, **kwargs):
        # Only authenticated and admin users can create
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Header created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class HeaderGetByIdView(RetrieveUpdateDestroyAPIView):
    queryset = Header.objects.all()
    serializer_class = HeaderSerializer
    # permission_classes = [permissions.IsAuthenticated]
    # authentication_classes = [JWTAuthentication]

    def retrieve(self, request, *args, **kwargs):
        # Get the object to retrieve
        instance = self.get_object()

        # Serialize the object
        serializer = self.get_serializer(instance)

        # Return the data along with a custom message
        return Response(
            {"message": "Header retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )

    @authentication_classes([JWTAuthentication])
    @permission_classes([permissions.IsAuthenticated, permissions.IsAdminUser])
    def destroy(self, request, *args, **kwargs):
        # Get the object to delete
        instance = self.get_object()
        
        # Perform the deletion
        self.perform_destroy(instance)
        
        # Return a custom success message after deletion
        return Response(
            {"message": "Header deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )

    @authentication_classes([JWTAuthentication])
    @permission_classes([permissions.IsAuthenticated, permissions.IsAdminUser])
    def update(self, request, *args, **kwargs):
        # Get the object to update
        instance = self.get_object()
        
        # Perform the update
        serializer = self.get_serializer(instance, data=request.data)
        
        if serializer.is_valid():
            serializer.save()
            # Return a custom success message after the update
            return Response(
                {"message": "Header updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# WhyChooseUs Section


class WhyChooseUsListCreateView(ListCreateAPIView):
    queryset = WhyChooseUs.objects.all()
    serializer_class = WhyChooseUsSerializer
    permission_classes = [AllowAny]  # Allow anyone to access the list view

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {"message": "WhyChooseUs retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )

    def create(self, request, *args, **kwargs):
        self.permission_classes = [IsAuthenticated , IsAdminUser]
        self.authentication_classes = [JWTAuthentication]
        self.check_permissions(request)  # Apply permission check

        serialize = self.get_serializer(data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response(
                {"message": "WhyChooseUs created successfully", "data": serialize.data},
                status=status.HTTP_201_CREATED
            )
        return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)



class WhyChooseUsGetByIdView(RetrieveUpdateDestroyAPIView):
    queryset = WhyChooseUs.objects.all()
    serializer_class = WhyChooseUsSerializer

    def retrieve(self , request , *args, **kwargs):
        instance = self.get_object()
        serialize = self.get_serializer(instance)
        return Response(
            {"message": "WhyChooseUs retrieved successfully", "data": serialize.data},
            status=status.HTTP_200_OK
        )

class WhyChooseUsUpdateDestroyView(RetrieveUpdateDestroyAPIView):
    queryset = WhyChooseUs.objects.all()
    serializer_class = WhyChooseUsSerializer
    permission_classes = [permissions.IsAuthenticated , permissions.IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def destroy(self , request , *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "WhyChooseUs deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )

    def update(self , request , *args, **kwargs):
        instance = self.get_object()
        serialize = self.get_serializer(instance , data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response(
                {"message": "WhyChooseUs updated successfully", "data": serialize.data},
                status=status.HTTP_200_OK
            )
        return Response(serialize.errors , status=status.HTTP_400_BAD_REQUEST)
    





# Testimonial Section


class TestimonialListView(ListAPIView):
    queryset = Testimonial.objects.all()
    serializer_class = TestimonialSerializer
    permission_classes = [AllowAny]  # Allow anyone to access the list view

class TestimonialGetByIdView(RetrieveAPIView):
    queryset = Testimonial.objects.all()
    serializer_class = TestimonialSerializer
    permission_classes = [AllowAny]  # Allow anyone to access the list view


class TestimonialCreateView(CreateAPIView):
    queryset = Testimonial.objects.all()
    serializer_class = TestimonialSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]
    def create(self , request , *args, **kwargs):
        serialize = self.get_serializer(data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response(
                {"message": "Testimonial created successfully", "data": serialize.data},
                status=status.HTTP_201_CREATED
            )
        return Response(serialize.errors , status=status.HTTP_400_BAD_REQUEST)
    

class TestimonialUpdateView(UpdateAPIView):
    queryset = Testimonial.objects.all()
    serializer_class = TestimonialSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def update(self , request , *args, **kwargs):
        instance = self.get_object()
        serialize = self.get_serializer(instance , data = request.data)
        if serialize.is_valid():
            serialize.save()
            return Response(
                {"message": "Testimonial updated successfully", "data": serialize.data},
                status=status.HTTP_200_OK
            )
        return Response(serialize.errors , status=status.HTTP_400_BAD_REQUEST)
    

class TestimonialDeleteView(DestroyAPIView):
    queryset = Testimonial.objects.all()
    serializer_class = TestimonialSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def destroy(self , request , *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "Testimonial deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
    


# SocialMedia Section

class SocialMediaListView(ListAPIView):
    queryset = SocialMedia.objects.all()
    serializer_class = SocialMediaSerializer
    permission_classes = [AllowAny]  # Allow anyone to access the list view

class SocialMediaGetByIdView(RetrieveAPIView):
    queryset = SocialMedia.objects.all()
    serializer_class = SocialMediaSerializer
    permission_classes = [AllowAny]  # Allow anyone to access the list view


class SocialMediaCreateView(CreateAPIView):
    queryset = SocialMedia.objects.all()
    serializer_class = SocialMediaSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]
    def create(self , request , *args, **kwargs):
        serialize = self.get_serializer(data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response(
                {"message": "SocialMedia created successfully", "data": serialize.data},
                status=status.HTTP_201_CREATED
            )
        return Response(serialize.errors , status=status.HTTP_400_BAD_REQUEST)
    

class SocialMediaUpdateView(UpdateAPIView):
    queryset = SocialMedia.objects.all()
    serializer_class = SocialMediaSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def update(self , request , *args, **kwargs):
        instance = self.get_object()
        serialize = self.get_serializer(instance , data = request.data)
        if serialize.is_valid():
            serialize.save()
            return Response(
                {"message": "SocialMedia updated successfully", "data": serialize.data},
                status=status.HTTP_200_OK
            )
        return Response(serialize.errors , status=status.HTTP_400_BAD_REQUEST)
    

class SocialMediaDeleteView(DestroyAPIView):
    queryset = SocialMedia.objects.all()
    serializer_class = SocialMediaSerializer
    permission_classes = [IsAuthenticated , IsAdminUser]
    authentication_classes = [JWTAuthentication]

    def destroy(self , request , *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"message": "SocialMedia deleted successfully"},
            status=status.HTTP_204_NO_CONTENT
        )
