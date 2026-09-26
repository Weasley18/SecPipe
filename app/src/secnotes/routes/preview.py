"""Link previews (``GET /preview?url=``) behind the SSRF guard."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, Request, status

from secnotes.auth import CurrentUser
from secnotes.metrics import PREVIEW_BLOCKED
from secnotes.requestctx import client_ip
from secnotes.schemas import PreviewOut
from secnotes.ssrf import PreviewBlocked, PreviewFetcher, PreviewUnavailable

router = APIRouter(tags=["preview"])
security_log = logging.getLogger("secnotes.security")


@router.get("/preview", response_model=PreviewOut)
def preview(request: Request, user: CurrentUser, url: str = Query(min_length=1, max_length=2048)) -> PreviewOut:
    fetcher: PreviewFetcher = request.app.state.preview_fetcher
    try:
        final_url, title, description = fetcher.fetch(url)
    except PreviewBlocked as exc:
        security_log.warning(
            "preview blocked",
            extra={
                "event": "preview_blocked",
                "reason": exc.reason,
                "target_host": exc.host,
                "target_address": exc.address,
                "user_id": user.id,
                "client_ip": client_ip(request),
            },
        )
        PREVIEW_BLOCKED.labels(exc.reason).inc()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL not allowed") from exc
    except PreviewUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="preview unavailable") from exc
    return PreviewOut(url=final_url, title=title, description=description)
