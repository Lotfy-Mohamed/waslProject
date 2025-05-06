from rest_framework import serializers
from .models import Package, PackageOrder

class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Package
        fields = ['id', 'name', 'description', 'price', 'duration_in_days', 'benefits']

class PackageOrderSerializer(serializers.ModelSerializer):
    package = serializers.PrimaryKeyRelatedField(queryset=Package.objects.all())

    class Meta:
        model = PackageOrder
        fields = ['id', 'user', 'package', 'name', 'email', 'phone', 'created_at']

    def validate_package(self, value):
        """
        Validate that the provided package exists in the database.
        """
        if not Package.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Invalid package ID.")
        return value

    def create(self, validated_data):
        """
        Customize the create method to handle logged-in and non-logged-in users.
        """
        request = self.context['request']
        user = request.user

        if user.is_authenticated:
            # If the user is logged in, populate the name, email, and phone from the user account
            validated_data['name'] = user.username
            validated_data['email'] = user.email
            # validated_data['phone'] = user.profile.phone if hasattr(user, 'profile') else ''  # Adjust based on your User model
            validated_data['phone'] = user.phone  # Adjust based on your User model
            validated_data['user'] = user
        else:
            # Ensure all required fields are provided for non-authenticated users
            if not all(k in validated_data for k in ['name', 'email', 'phone']):
                raise serializers.ValidationError("Name, email, and phone are required for non-authenticated users.")

        return super().create(validated_data)



class GetAllOrdersSerializer(serializers.ModelSerializer):
    # package = serializers.PrimaryKeyRelatedField(queryset=Package.objects.all())
    # package = PackageSerializer()
    class Meta:
        model = PackageOrder
        fields = ['id', 'user', 'package', 'name', 'email', 'phone', 'created_at']