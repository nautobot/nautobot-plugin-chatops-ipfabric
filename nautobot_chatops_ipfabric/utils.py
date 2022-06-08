def create_regex(string: str) -> str:
    """Takes a string and returns a case insensitive regex."""
    regex = "^"
    for i in string.upper():
        if i.isalpha():
            regex += f"[{i}{i.lower()}]"
        else:
            regex += i
    return regex + "$"