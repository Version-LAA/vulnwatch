from django.shortcuts import render
from django.views.generic import ListView
from django.db.models import Avg, Count, Max, Q
from django.core.paginator import Paginator

from .models import Vulnerability
# Create your views here.


class VulnerabilityListView(ListView):
    model = Vulnerability
    template_name = 'home.html'
    paginate_by = 5

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        custom_queryset = Vulnerability.objects.filter(
            cvss_score__isnull=False)
        paginator = Paginator(custom_queryset, self.paginate_by)
        page_number = self.request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        context['page_obj'] = page_obj
        context['paginator'] = paginator
        # context['filtered_vulnerabilities'] = Vulnerability.objects.filter(
        #     cvss_score__isnull=False)
        stats = Vulnerability.objects.aggregate(
            avg_cvss=Avg('cvss_score'),
            total=Count('id'),
            critical_count=Count('id', filter=Q(cvss_score__gte=9.0))
        )
        context['stats'] = stats
        return context
