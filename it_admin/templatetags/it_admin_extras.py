from django import template

register = template.Library()


@register.filter
def get_item(mapping, key):
    """Dictionary lookup by key inside templates (``dict|get_item:key``)."""
    if mapping is None:
        return None
    return mapping.get(key)
