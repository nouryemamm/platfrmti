from fastapi import APIRouter
from services.url_service import get_url_report
 
router = APIRouter(
    prefix="/url",           # Tous les endpoints commenceront par /url
    tags=["URL Enrichment"] 
)

@router.get("/")
def url_lookup(param: str):
    return get_url_report(param)