from django.db import models
from django.utils import timezone
from django.urls import reverse

# Create your models here.


class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=20, unique=True,  db_index=True)
    title = models.CharField(max_length=200, blank=True, null=True)
    cvss_score = models.DecimalField(
        max_digits=4, decimal_places=1, null=True, blank=True)
    source = models.CharField(max_length=200)
    description = models.TextField()
    epss_score = models.DecimalField(
        max_digits=11, decimal_places=11, null=True, blank=True)
    application_name = models.CharField(max_length=200, blank=True, null=True)
    version = models.CharField(max_length=200, blank=True, null=True)
    published_date = models.DateField()
    date_added = models.DateField(default=timezone.now)
    last_modification_date = models.DateField()
    is_kev = models.BooleanField(default=False)
    references = models.JSONField(default=list, blank=True, null=True)

    def epss_percentage(self):
        if self.epss_score:
            return f"{float(self.epss_score) * 100:.2f}%"
        return "N/A"

    def __str__(self):
        return self.cve_id

    def get_absolute_url(self):
        return reverse("vulnerability_detail", kwargs={"pk": self.pk})

    class Meta:
        ordering = ["-cvss_score"]
        verbose_name_plural = "vulnerabilities"
        db_table = "vulnerabilities"


class AffectedProduct(models.Model):
    vendor = models.CharField(max_length=300, default='unknown')
    name = models.CharField(max_length=200, blank=True, null=True)
    version = models.JSONField(default=list, blank=True, null=True)
    vulnerability = models.ForeignKey(
        Vulnerability,
        to_field='cve_id',
        on_delete=models.CASCADE,
        related_name='affected_products'
    )

    def __str__(self):
        return self.name or f"Unknown product ({self.vulnerability.cve_id})"

    class Meta:
        unique_together = ['vulnerability', 'vendor', 'name']
        verbose_name_plural = "affected products"
