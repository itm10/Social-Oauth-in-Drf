from django.urls import path
from .views import WarehouseCheckView

urlpatterns = [
    path('check-availability/', WarehouseCheckView.as_view()),
]