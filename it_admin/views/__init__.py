"""IT / Admin portal views.

Split by concern; every module re-exports through this package so
``it_admin.urls`` and existing imports (``from it_admin import views``)
keep working.

Rule for every view here: AUTHENTICATION → AUTHORIZATION → ACTION, enforced
by the ``accounts.decorators`` stack. Identity administration never touches
investigation data.
"""
from .approvals import *  # noqa: F401,F403
from .bulk import *  # noqa: F401,F403
from .dashboard import *  # noqa: F401,F403
from .officers import *  # noqa: F401,F403
from .registries import *  # noqa: F401,F403
from .security import *  # noqa: F401,F403
from .access import *  # noqa: F401,F403
