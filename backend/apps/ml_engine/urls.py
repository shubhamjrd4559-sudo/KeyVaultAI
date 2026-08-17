from django.urls import path
from .views import MLPredictView

urlpatterns = [
    path("predict/", MLPredictView.as_view(), name="ml-predict"),
]
