from django.urls import path
from .views import VulnerabilityListView, VulnerabilityDetailView


urlpatterns = [
    path("vulnerability/<int:pk>/", VulnerabilityDetailView.as_view(),
         name="vulnerability_detail"),
    path('', VulnerabilityListView.as_view(), name='home')
]
