from django.db import models

# Create your models here.


class Vulnerability(models.Model):
    cve_id = models.CharField(max_length=20, unique=True,  db_index=True)
    title = models.CharField(max_length=200)
    cvss_score = models.DecimalField(
        max_digits=4, decimal_places=1, null=True, blank=True)
    source = models.CharField(max_length=200)
    description = models.TextField()
    epss_score = models.DecimalField(
        max_digits=5, decimal_places=1, null=True, blank=True)
    application_name = models.CharField(max_length=200)
    version = models.CharField(max_length=200)
    published_date = models.DateField()
    date_added = models.DateField()
    last_modification_date = models.DateField()
    is_kev = models.BooleanField(default=False)

    def __str__(self):
        return self.cve_id

    class Meta:
        ordering = ["-cvss_score"]
        verbose_name_plural = "vulnerabilities"
        db_table = "vulnerabilities"
