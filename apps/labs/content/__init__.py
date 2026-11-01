"""Registry of all lab definitions. Add new labs to LABS."""

from . import (l00_orientation, l01_concepts, l02_number_theory, l03_symmetric,
               l04_public_key)
from .base import LabDef

LABS: list[LabDef] = [
    l00_orientation.LAB,
    l01_concepts.LAB,
    l02_number_theory.LAB,
    l03_symmetric.LAB,
    l04_public_key.LAB,
]

REGISTRY: dict[str, LabDef] = {lab.slug: lab for lab in LABS}


def get(slug: str) -> LabDef | None:
    return REGISTRY.get(slug)
