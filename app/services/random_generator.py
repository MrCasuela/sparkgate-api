import secrets
import string


DEFAULT_LENGTH = 16
MIN_LENGTH = 12
MAX_LENGTH = 64


def generate(
    length: int = DEFAULT_LENGTH,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    if length < MIN_LENGTH or length > MAX_LENGTH:
        raise ValueError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}")

    chars = ""
    required = []

    if use_lower:
        chars += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        chars += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        chars += string.digits
        required.append(secrets.choice(string.digits))
    if use_symbols:
        chars += string.punctuation
        required.append(secrets.choice(string.punctuation))

    if not chars:
        raise ValueError("At least one character set must be selected")

    password = required + [secrets.choice(chars) for _ in range(length - len(required))]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)
