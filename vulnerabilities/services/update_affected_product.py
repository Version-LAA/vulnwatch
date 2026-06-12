import logging
from vulnerabilities.models import AffectedProduct, Vulnerability

logger = logging.getLogger(__name__)


def save_to_affected_products_db(product_list):

    for product in product_list:
        try:
            vuln = Vulnerability.objects.get(cve_id=product['vulnerability'])
            AffectedProduct.objects.update_or_create(
                vulnerability=vuln,
                name=product['name'],
                defaults={
                    'vendor': product.get('vendor'),
                    'version': product.get('version', [])
                }
            )
            logger.info(
                f"Updated the affected products db for {vuln.cve_id}")
        except Vulnerability.DoesNotExist:
            logger.warning(
                f"Vulnerability {product['vulnerability']} not found — skipping affected product")
