"""Passphrase generator.

Threat: people reuse one weak password everywhere because strong ones are
hard to remember. A passphrase of random words is both strong AND memorable
(e.g. "Tiger-Lamp-River-Cloud-Mango-Seven").

Security idea: use the `secrets` module, never `random`. `random` is
predictable (it is meant for games and simulations); `secrets` uses the
operating system's cryptographically secure randomness.
"""

import math
import secrets

# 256 short, common, easy-to-spell words. With 256 words, each word adds
# log2(256) = 8 bits of entropy. The words must be picked at RANDOM by the
# computer - a human "randomly" choosing words is not random at all.
WORDS = """
able acid aged also area army away baby back ball band bank base bath bear
beat bell belt best bird blue boat body bone book boot born boss both bowl
bread brick bush cake calm camp card care cart case cash cave chair chalk
chess city clay cliff clock cloud coat code coin cold cook cool corn cow
crab crow cube cup dark data dawn deer desk dish dock door dove duck dust
eagle earth east echo edge egg elbow elk emu fair farm fern field fig film
fire fish flag flat flute foam fog food fork fox frog fruit game gate gift
glass glow goat gold golf grape grass green grid gulf hair hall hand harp
hawk heart hill home honey hook horn horse house ice idea inch ink iron
island jam jar jazz jeep jelly jet joke juice kettle key kid king kite
kiwi knee knot lab lake lamp lane leaf lemon lens lily lime lion list lock
log loop lunch mango map maple mask meal melon milk mint moon moss moth
mouse mud nail nest net night noon north nose note nut oak oat ocean olive
onion orange owl paint palm pan paper park path peach pearl pen piano pie
pig pilot pine pink pipe plum pond pony pool port pot quiz rabbit rain
river road robin rock roof rope rose ruby sail salt sand seal seed shell
ship shoe silk silver sky snow sock sofa song soup star stone sugar sun
swan table tea tent tiger toast tooth tower train tree tulip van vase
wave whale wheat wind wolf wood yard year yoga zebra zinc zone
""".split()


def generate_passphrase(word_count=6, separator="-", add_number=True):
    """Build a passphrase like 'Maple-Owl-Tent-River-Jazz-Pearl-42'."""
    words = [secrets.choice(WORDS).capitalize() for _ in range(word_count)]
    if add_number:
        words.append(str(secrets.randbelow(100)))
    return separator.join(words)


def passphrase_entropy_bits(word_count=6, add_number=True):
    """Guessing difficulty in bits, assuming the attacker knows our word list."""
    bits = word_count * math.log2(len(set(WORDS)))
    if add_number:
        bits += math.log2(100)
    return bits
