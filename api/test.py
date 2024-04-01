import requests
from fastapi import status
import json
import asyncio




BASE_URL = 'http://127.0.0.1:8000/'


def test_info():
    info_url = BASE_URL + 'info'
    response = requests.get(info_url)
    assert response.status_code == 200
    assert response.json()
    print(response)


def test_signup():
    signup_url = BASE_URL + 'signup'
    user = {
        "username": "loki",
        "fullname": "loki myman",
        "role":"user",
        "email": f"lokinweje@gmail.com",
        "password": "Test@password34",
    }

    response = requests.post(signup_url, json=user)
    assert response.json()
    print(response)

def test_login():
    login_url = BASE_URL + "login"

    test_user_data = {
        "email": "lokinweje@gmail.com",
        "password": "Test@password34",
    }

    response = requests.post(login_url, json=test_user_data)

    # Assert status code
    assert response.status_code == status.HTTP_200_OK, f"Unexpected status code: {response.status_code}"

    # Assert access token presence
    assert "access_token" in response.json(), "Missing access token in response"

    # Assert refresh token presence
    assert "refresh_token" in response.json(), "Missing refresh token in response"

    response_json = response.json()
    print(response_json)

def test_change_password():
    VALID_USER_EMAIL = "lokinweje@gmail.com"
    VALID_USER_PASSWORD = "Test@password34"
    change_password_url = BASE_URL + 'change-password'
    old_password = VALID_USER_PASSWORD
    new_password = "Newtestpassword113"
    change_password_data = {
    "email": VALID_USER_EMAIL,
    "old_password": old_password,
    "new_password": new_password,
    }
    change_password_response = requests.post(change_password_url, json=change_password_data)
    print(change_password_response.json)


def test_get_users():

   # Define query parameters
    params = {
        "page": 1,
        "per_page": 10,
        "sort_by": "id",
        "sort_order": "asc",
        "filter_by": None,
    }

    # Make the request with the defined parameters
    response = requests.get("http://127.0.0.1:8000/users", params=params)

    # Check if the request was successful (status code 200)
    assert response.status_code == 200

    # Add more assertions based on your expected response format
    response_json = response.json()
    print(response_json)

def test_read_user():
  
    ruser_url  =  "http://127.0.0.1:8000/users/2" 
    
    # Make the request to the endpoint
    response = requests.get(ruser_url)
    response_json = response.json()
    print(response_json)

    # Check if the request was successful (status code 200)
    assert response.status_code == 200
    if response.status_code == 404:
        assert "User not found" in response.text

def test_create_preference():
    # Create a preference payload
    preference_payload = {
        "user_id":2,
        "theme": "dark",
        "notification": True,
        "language_preference": "en",
    }
    preference_url = BASE_URL+'preferences'
    response = requests.post(preference_url, json=preference_payload)
    # Check if the response is successful
    assert response.status_code == 201

    # Parse the response JSON
    preference_data = response.json()

    # Check if the returned data matches the request payload
    assert preference_data["user_id"] == preference_payload["user_id"]
    assert preference_data["theme"] == preference_payload["theme"]
    assert preference_data["notification"] == preference_payload["notification"]
    assert preference_data["language_preference"] == preference_payload["language_preference"]

def test_get_preference():
    getpreference_url  =  BASE_URL + 'preferences/2'
    # Make the request to the endpoint
    response = requests.get(getpreference_url)

    # Deserialize the JSON response into a dictionary
    preference_dict = response.json()

    # Validate the response against the expected schema
    assert "id" in preference_dict
    assert "user_id" in preference_dict
    assert "theme" in preference_dict
    assert "notification" in preference_dict
    assert "language_preference" in preference_dict
    assert "created_at" in preference_dict
    print(preference_dict)

def test_update_preference():
    updated_preference_data = {
        "theme": "light",
        "notification": True,
        "language_preference": "en",
    }
    user_id = 2
    # Make the PUT request to update the preference
    url = f"http://localhost:8000/update/preferences/{user_id}"
    response = requests.put(url, json=updated_preference_data)
    # Check that the request was successful (status code 200)
    assert response.status_code == 200

    # Check that the response matches the updated preference
    updated_preference = response.json()
    assert updated_preference["theme"] == updated_preference_data["theme"]
    assert updated_preference["notification"] == updated_preference_data["notification"]
    assert updated_preference["language_preference"] == updated_preference_data["language_preference"]
    print(updated_preference)


def test_create_incidence_report():
    incidence_report_url = BASE_URL + "incidence-report"

    # Sample incidence report data
    incidence_report_data = {
        "incidence_type": "Accident",
        "location": "City Center",
        "severity": "High",
        "user_id": 1  # Replace with a valid user ID from your database
    }

    # Make a POST request to create an incidence report
    response = requests.post(incidence_report_url, json=incidence_report_data)

    # Check if the request was successful (status code 200 or 201)
    assert response.status_code in [200, 201]

    # Check if the response JSON has the expected structure
    assert "id" in response.json()
    assert "created_at" in response.json()
    assert response.json()["incidence_type"] == incidence_report_data["incidence_type"]
    assert response.json()["location"] == incidence_report_data["location"]
    assert response.json()["severity"] == incidence_report_data["severity"]
    assert response.json()["user_id"] == incidence_report_data["user_id"]

def test_read_incidence_report():
    response = requests.post(f"{BASE_URL}incidence-report", json={"incidence_type": "Test", "location": "TestLocation", "severity": "Low", "user_id": 1})
    assert response.status_code == 201
    report_id = response.json()["id"]
    # Testing for the read endpoint
    response = requests.get(f"{BASE_URL}incidence-report/{report_id}")
    assert response.status_code == 200

    # Validate the response content
    incidence_report = response.json()
    assert incidence_report["id"] == report_id
    assert incidence_report["incidence_type"] == "Test"
    assert incidence_report["location"] == "TestLocation"
    assert incidence_report["severity"] == "Low"
    assert incidence_report["user_id"] == 1
 
    # Clean up: Delete the test incidence report (optional)
    response = requests.delete(f"{BASE_URL}incidence-report/delete/{report_id}")
    assert response.status_code == 200

    # Confirm that the report is deleted 
    response = requests.get(f"{BASE_URL}incidence-report/{report_id}")
    assert response.status_code == 404


def test_create_feedback_report():
    url = f"{BASE_URL}feedback-reports"
    payload = {
        "currenttimestamp": "2023-01-01T12:00:00",
        "user_id": 1,
        "feedback": "This is a test feedback",
        "incidence_report_id": 1,  
        "report_type": "issue",
        "report_data_path": "/path/to/report/data",
    }

    response = requests.post(url, json=payload)

    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["user"]["id"] == payload["user_id"]
    assert data["incident_report"]["id"] == payload["incidence_report_id"]



