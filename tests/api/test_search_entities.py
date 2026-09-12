import pytest
from httpx import ASGITransport, AsyncClient

from src.main import app


@pytest.mark.asyncio
async def test_entity_lookup() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {"ioc": "192.168.1.1", "ioc_type": "ipv4"}
        response = await ac.post("/api/v1/entities/lookup", json=payload)
    
    assert response.status_code == 200
    assert isinstance(response.json(), list)

@pytest.mark.asyncio
async def test_hybrid_search() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {"query": "APT29 stealthy techniques", "top_k": 10}
        response = await ac.post("/api/v1/search/hybrid", json=payload)
    
    assert response.status_code == 200
    assert isinstance(response.json(), list)
