import httpx
import requests
from fastapi import APIRouter

router = APIRouter()


@router.get("/preview")
def bad_httpx(url: str):
    # ruleid: secnotes-ssrf-user-url
    return httpx.get(url, follow_redirects=True).text


@router.get("/fetch")
def bad_requests(target_url: str):
    # ruleid: secnotes-ssrf-user-url
    return requests.get(target_url, timeout=5).text


@router.get("/safe")
def good(url: str, fetcher=None):
    target = validate_url(url)
    # ok: secnotes-ssrf-user-url
    return httpx.get(target, timeout=3).text


@router.get("/delegated")
def good_delegated(url: str, fetcher=None):
    # ok: secnotes-ssrf-user-url
    return fetcher.fetch(url)
