from django.contrib import admin
from .models import Vulnerability, AffectedProduct
# Register your models here.


class SettingVulnerability(admin.ModelAdmin):
    list_display = ('cve_id', 'cvss_score', 'published_date')


class SettingAffectedProduct(admin.ModelAdmin):
    list_display = ('vulnerability', 'vendor', 'name')


admin.site.register(Vulnerability, SettingVulnerability)
admin.site.register(AffectedProduct, SettingAffectedProduct)
