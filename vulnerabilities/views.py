from django.shortcuts import render
from django.views.generic import ListView
from django.db.models import Avg, Count, Max, Q
from django.core.paginator import Paginator
from datetime import timedelta
from django.utils import timezone

from .models import Vulnerability
# Create your views here.


class VulnerabilityListView(ListView):
    model = Vulnerability
    template_name = 'home.html'
    context_object_name = 'vulnerabilities'
    ordering = ['-published_date']

    def get_queryset(self):
        return Vulnerability.objects.filter(
            cvss_score__isnull=False).order_by('-published_date')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        seven_days_ago = timezone.now() - timedelta(days=7)
        stats = Vulnerability.objects.aggregate(
            avg_cvss=Avg('cvss_score'),
            total=Count('id', filter=Q(
                cvss_score__gte=1.0
            )),
            critical_count=Count('id', filter=Q(
                cvss_score__gte=9.0, published_date__gte=seven_days_ago))
        )

        context['stats'] = stats
        return context
