from app import create_app


def client():
    return create_app({"TESTING": True}).test_client()


def test_home_page_loads():
    response = client().get("/")
    assert response.status_code == 200
    assert b"PhishGuard" in response.data


def test_health_endpoint():
    response = client().get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_prediction_endpoint():
    response = client().post("/api/predict", json={"url": "http://198.51.100.42/verify-account/login"})
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["success"] is True
    assert payload["data"]["risk_score"] >= 50
    assert payload["data"]["reasons"]


def test_rejects_unsupported_scheme():
    response = client().post("/api/predict", json={"url": "javascript:alert(1)"})
    assert response.status_code == 400
