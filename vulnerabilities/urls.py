from django.urls import path
from .views import VulnerabilityListView


urlpatterns = [
    path('', VulnerabilityListView.as_view(), name='home')
]
