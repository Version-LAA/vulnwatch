from django.shortcuts import render
from django.views.generic import ListView
from django.db.models import Avg, Count, Max, Q

from .models import Vulnerability
# Create your views here.


class VulnerabilityListView(ListView):
    model = Vulnerability
    template_name = 'home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['filtered_vulnerabilities'] = Vulnerability.objects.filter(
            cvss_score__isnull=False)
        stats = Vulnerability.objects.aggregate(
            avg_cvss=Avg('cvss_score'),
            total=Count('id'),
            critical_count=Count('id', filter=Q(cvss_score__gte=9.0))
        )
        context['stats'] = stats
        return context
