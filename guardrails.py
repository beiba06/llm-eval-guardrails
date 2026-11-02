"""Input and output checks that sit around a model or app. Pure functions, except the optional Haiku classifier."""
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"))
HOMOGLYPHS = str.maketrans("аеорсухіјѕАЕОРСУХІВМНТКαοετρ", "aeopcyxijsAEOPCYXIBMHTKaoetp")


def fold(text: str) -> str:
    """Undo the tricks that change how text looks to a filter but not to a reader. Case and line breaks stay."""
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH).translate(HOMOGLYPHS)


def normalise(text: str) -> str:
    """fold, then lower case on a single line: the form the phrase patterns match against."""
    return re.sub(r"\s+", " ", fold(text)).strip().lower()
