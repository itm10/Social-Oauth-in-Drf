from rest_framework import serializers


class CheckAvailabilitySerializer(serializers.Serializer):
    product_id = serializers.IntegerField(required=True)
    quantity = serializers.IntegerField(required=False, default=1)
