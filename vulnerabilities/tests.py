from django.test import TestCase
from django.urls import reverse
from .models import Vulnerability
from django.utils import timezone
# Create your tests here.


class HomepageTests(TestCase):
    def test_url_exists_at_correct_location(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_url_available_by_name(self):
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 200)

    def test_template_name_correct(self):
        response = self.client.get(reverse("home"))
        self.assertTemplateUsed(response, "home.html")


class VulnerabilityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.vulnerability = Vulnerability.objects.create(
            cve_id='CVE-2026-12345',
            title='This is a test - vuln',
            cvss_score=10.0,
            source='cve.org',
            description='This Is a Test Description',
            epss_score=0.000349301,
            application_name='test application',
            version='1.0-2.0',
            published_date='2026-06-11',
            date_added='2026-06-11',
            last_modification_date='2026-06-11',
            is_kev=False,
            references=''


        )

    def test_model_content(self):
        self.assertEqual(self.vulnerability.title, 'This is a test - vuln')
