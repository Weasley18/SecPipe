"""Link previews (``GET /preview?url=``)."""

from __future__ import annotations

import re

import httpx
from fastapi import APIRouter

from secnotes.auth import CurrentUser
from secnotes.schemas import PreviewOut

router = APIRouter(tags=["preview"])
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@router.get("/preview", response_model=PreviewOut)
def preview(url: str, user: CurrentUser) -> PreviewOut:
    # PLANTED FLAW #6: SSRF, the server fetches any URL, follows redirects and
    # can reach cloud metadata (169.254.169.254) or in-cluster services.
    response = httpx.get(url, follow_redirects=True, timeout=5)
    match = _TITLE.search(response.text)
    title = match.group(1).strip() if match else None
    return PreviewOut(url=str(response.url), title=title, description=None)
