"""Registry of all lab definitions. Add new labs to LABS."""

from . import (l00_orientation, l01_concepts, l02_number_theory, l03_symmetric,
               l04_public_key, l05_integrity, l06_pki, l07_auth, l08_transport,
               l09_wireless, l10_email_ip)
from .base import LabDef

LABS: list[LabDef] = [
    l00_orientation.LAB,
    l01_concepts.LAB,
    l02_number_theory.LAB,
    l03_symmetric.LAB,
    l04_public_key.LAB,
    l05_integrity.LAB,
    l06_pki.LAB,
    l07_auth.LAB,
    l08_transport.LAB,
    l09_wireless.LAB,
    l10_email_ip.LAB,
]

REGISTRY: dict[str, LabDef] = {lab.slug: lab for lab in LABS}


def get(slug: str) -> LabDef | None:
    return REGISTRY.get(slug)
