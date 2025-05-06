from rest_framework import serializers
from .models import Service, ServiceStep , ServiceOrder , ServiceOrderStep
from auth_flow.models import AllUsers as User , Employee

class ServiceStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceStep
        fields = ['id', 'name', 'step_description','status', 'step_price', 'payment_status' , 'requirements_data_from_user', 'files', 'data_req_user', 'data_user_file_upload', 'step_result_text', 'step_result_file']

class ServiceSerializer(serializers.ModelSerializer):
    steps = ServiceStepSerializer(many=True)

    def validate_benifits_service(self, value):
        """
        Validate that `benifits_service` follows the correct structure:
        - A list of dictionaries
        - Each dictionary must contain a "title" (string) and "names" (list of strings)
        """
        if not isinstance(value, list):
            raise serializers.ValidationError("Benefits must be a list of dictionaries.")
        for benefit in value:
            if not isinstance(benefit, dict):
                raise serializers.ValidationError("Each benefit must be a dictionary.")
            if "title" not in benefit or "names" not in benefit:
                raise serializers.ValidationError("Each benefit must contain 'title' and 'names' keys.")
            if not isinstance(benefit["title"], str):
                raise serializers.ValidationError("The 'title' field must be a string.")
            if not isinstance(benefit["names"], list) or not all(isinstance(name, str) for name in benefit["names"]):
                raise serializers.ValidationError("The 'names' field must be a list of strings.")
        return value
    
    class Meta:
        model = Service
        fields = ['id', 'name', 'description', 'sub_description', 'total_price','image_service', 'icon_service','benifits_service' , 'steps']
        
    
    def create(self, validated_data):
        # Extract the steps data
        steps_data = validated_data.pop('steps')
        
        # Create the Service instance
        service = Service.objects.create(**validated_data)
        
        # Create each step and associate it with the service
        for step_data in steps_data:
            ServiceStep.objects.create(service=service, **step_data)
        return service
    
    
    def update(self, instance, validated_data):
        # Extract the steps data
        steps_data = validated_data.pop('steps', None)

        # Update basic service data
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.description)
        instance.sub_description = validated_data.get('sub_description', instance.sub_description)
        instance.total_price = validated_data.get('total_price', instance.total_price)
        instance.image_service = validated_data.get('image_service', instance.image_service)
        instance.benifits_service = validated_data.get('benifits_service', instance.benifits_service)
        instance.icon_service = validated_data.get('icon_service', instance.icon_service)
        instance.save()

        # Update the steps if they are provided
        if steps_data is not None:
            # First, delete existing steps if they are not included in the request
            instance.steps.all().delete()

            # Then, create new steps
            for step_data in steps_data:
                ServiceStep.objects.create(service=instance, **step_data)

        return instance


class ServiceImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['image_service']



# ServiceStep Serializer (to include full details of steps)
class ServiceStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceStep
        fields = ['id', 'name', 'step_description','status', 'requirements_data_from_user', 'files', 'data_req_user','data_user_file_upload', 'step_price', 'payment_status' , 'step_result_text', 'step_result_file']


# Service Serializer (to include full service details and steps)
class serviceForOrderSerializer(serializers.ModelSerializer):
    # steps = ServiceStepSerializer(many=True, read_only=True)

    class Meta:
        model = Service
        fields = ['id', 'name', 'description', 'sub_description', 'total_price']
        # fields = ['id', 'name', 'description', 'sub_description', 'total_price', 'steps']
        

# ServiceOrderStep Serializer
class ServiceOrderStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceOrderStep
        fields = ['id', 'step', 'status', 'payment_status', 'step_price' , 'name', 'step_description' ,'requirements_data_from_user', 'files', 'data_req_user' , 'data_user_file_upload' , 'step_result_text', 'step_result_file']
        
        
# ServiceOrder Serializer (to include full service and service steps)
    # assigned_employee = serializers.PrimaryKeyRelatedField(queryset=Employee.objects.all(), required=False)
    # assigned_employee = serializers.ReadOnlyField(source='assigned_employee.user.first_name')
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User  # Replace with your actual User model
        fields = ['id', 'first_name', 'last_name', 'email', 'phone']

class EmployeeSerializer(serializers.ModelSerializer):
    user = UserSerializer()  # Include nested User details

    class Meta:
        model = Employee  # Replace with your actual Employee model
        fields = ['id', 'user', 'position']  # Add the fields you need

class ServiceOrderSerializer(serializers.ModelSerializer):
    service = serviceForOrderSerializer()  # Include full service data, including steps
    assigned_employee = EmployeeSerializer()  # Use the nested serializer for employee
    steps = ServiceOrderStepSerializer(many=True, read_only=True)
    user = UserSerializer()  # Include nested User details
    class Meta:
        model = ServiceOrder
        fields = ['id', 'user', 'status', 'assigned_employee', 'created_at', 'service', 'steps']

class CreateOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceOrder
        fields = '__all__'


class UpdateOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceOrder
        fields = '__all__'
        
        



class ServiceForHomeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['id', 'name', 'sub_description' , 'icon_service']
        

class ServiceForSinglePageByIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['id', 'name', 'description', 'sub_description','image_service', 'benifits_service']
        
        
class AllserviceNameIDOnlySerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['id', 'name' , 'icon_service']