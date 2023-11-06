
def to_camel(string: str) -> str:
    #return ''.join(word.capitalize() for word in string.split('_'))
    if not string:
        return string
    s = ''.join(word.capitalize() for word in string.split('_'))
    return s[0].lower() + s[1:]
