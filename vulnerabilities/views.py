from django.shortcuts import render
from django.views.generic import ListView

from .models import Vulnerability
# Create your views here.


class VulnerabilityListView(ListView):
    model = Vulnerability
    template_name = 'home.html'
