"""Plain English prose for the classical-cipher tasks. Written for this course
(no copyright concerns); long enough that letter frequencies look like English."""

PARAGRAPHS = [
    "For most of history, secret writing was a craft practised by a handful of clerks "
    "who served kings, generals and merchants. A message was only as safe as the "
    "messenger who carried it and the method used to disguise it. When the messenger "
    "was captured, the enemy would sit with the letter for days, counting symbols and "
    "looking for patterns, until the meaning slowly came out of the noise.",

    "The simplest disguise is to replace every letter with another one. Julius Caesar "
    "is said to have shifted each letter three places along the alphabet, so that the "
    "word attack became something no ordinary reader could understand. The weakness is "
    "obvious once it is pointed out: there are only twenty five possible shifts, and an "
    "attacker with patience can simply try them all before lunch.",

    "A more careful clerk scrambles the whole alphabet instead of shifting it. There are "
    "so many possible arrangements that nobody could ever try them one by one. Yet this "
    "cipher still falls quickly, because the language underneath leaves fingerprints. "
    "In English the letter e appears far more often than any other, followed by t and "
    "a, and short words such as the and and repeat again and again throughout any text.",

    "Arab scholars described frequency analysis more than a thousand years ago. The idea "
    "is to count how often each symbol appears in the secret message and compare the "
    "counts with those of the ordinary language. The most common symbol probably stands "
    "for the most common letter. With a few good guesses, whole words begin to appear, "
    "and each new word gives away more letters until the entire message can be read.",

    "To defeat counting, later writers used several alphabets in turn, chosen by a "
    "keyword. The same letter of the message could then be written in many different "
    "ways, which flattens the counts and hides the language. For three centuries this "
    "was called the indecipherable cipher. Then a retired officer noticed that repeated "
    "fragments in the secret text were separated by distances that shared a common "
    "factor, and that factor revealed the length of the keyword.",

    "Once the length of the keyword is known, the problem breaks into pieces. Every "
    "letter enciphered with the first letter of the key forms one group, every letter "
    "enciphered with the second forms another, and so on. Each group is nothing more "
    "than a simple shift, which falls to frequency analysis on its own. The lesson is "
    "that a clever system can fail because of one small regularity that leaks through.",

    "Modern engineers learned from these failures. A good cipher must hide every pattern "
    "in the message, even when the attacker knows exactly how the cipher works and can "
    "see huge amounts of encrypted traffic. All of the secrecy must live in the key, "
    "and the key must be long enough that trying every possibility is hopeless, even "
    "for an opponent with warehouses full of fast computers and many years to spare.",

    "Telephone engineers in the last century built machines that mixed a message with a "
    "long stream of random characters punched on paper tape. As long as the tape was "
    "truly random and never used twice, the result could not be broken by anyone. The "
    "trouble came when operators, short of fresh tape, reused old rolls to save time. "
    "Analysts on the other side noticed, lined up the messages, and read them both.",

    "Network security today rests on the same ideas. The data that crosses a campus "
    "network passes through switches, routers and radio links that anyone nearby may be "
    "able to observe. Encryption keeps the content private, but only if the keys are "
    "chosen well, stored safely and changed when they should be. A careless shortcut by "
    "one administrator can undo the work of the best mathematicians in the world.",

    "Students often ask why they should learn to break ciphers that nobody uses any "
    "more. The answer is that the habits of the codebreaker are the habits of the "
    "defender. Look for structure, assume the opponent is patient, count everything "
    "and never trust a design simply because it looks complicated. The old ciphers are "
    "small enough to break by hand, which makes their mistakes easy to remember.",
]

SENTENCES = [
    "Meet me by the old clock tower after the evening lecture",
    "The shipment leaves the harbour at dawn on the third day",
    "Bring the spare radio and the codebook to the usual place",
    "Our friend in the capital has agreed to carry the letters",
    "Do not use the telephone because the line is being watched",
    "The guards change at midnight so wait until a quarter past",
]

# The hidden answers. Distinctive, so a correct decryption is unmistakable.
PASSPHRASES = [
    "HARMATTAN", "ADINKRA", "SANKOFA", "KENTE", "BAOBAB", "KELEWELE", "ODWIRA",
    "AKWAABA", "TAMARIND", "MAHOGANY", "KAKUM", "BOSOMTWE", "NKYINKYIM", "GYENYAME",
    "PALMWINE", "SHEABUTTER", "HORNBILL", "SAVANNAH", "LAGOON", "PLANTAIN",
]

VIGENERE_KEYS = [
    "CIPHER", "SHANNON", "KUMASI", "SECRET", "LECTURE", "PACKET", "ROUTER", "BINARY",
    "KERCKHOFF", "ENIGMA", "FEISTEL", "TUNNEL", "SIGNAL", "VOLTAGE", "GATEWAY",
]
