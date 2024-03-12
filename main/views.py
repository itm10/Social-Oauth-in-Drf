from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status

from .models import Product, ProductMaterial, Warehouse
from .serializers import CheckAvailabilitySerializer


class WarehouseCheckView(GenericAPIView):
    serializer_class = CheckAvailabilitySerializer

    def post(self, request):

        product_id = request.data.get('product_id')
        quantity = request.data.get('quantity')

        try:
            product = Product.objects.get(pk=product_id)
            materials = ProductMaterial.objects.filter(product=product)
        except Product.DoesNotExist:
            return Response({'error': f'Product with ID {product_id} not found'}, status=status.HTTP_404_NOT_FOUND)

        product_materials = []
        for material in materials:
            warehouse_data = Warehouse.objects.filter(material=material.material).first()
            material_data = {}
            material_data['material_name'] = material.material.name
            if warehouse_data and warehouse_data.remainder >= material.quantity:
                material_data['warehouse_id'] = warehouse_data.id
                material_data['qty'] = warehouse_data.remainder - material.quantity
                material_data['price'] = warehouse_data.price
            else:
                material_data['warehouse_id'] = None
                material_data['qty'] = warehouse_data.remainder
                material_data['price'] = None
            product_materials.append(material_data)

        return Response({
            'product_name': product.name,
            'product_qty': quantity,
            'available_materials': product_materials
        })