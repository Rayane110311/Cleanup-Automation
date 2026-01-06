import json

RETRYABLE_ERRORS = {
    "Sandbox.Timedout",
    "States.Timeout",
    "States.TaskFailed",
    "Timeout",
    "Throttling",
    "PermissionError"
}

RETRYABLE_STATUS_CODES = {500, 502, 503, 504}

def lambda_handler(event, context):
    print(event)
    attempt = event["attempt"]
    max_attempts = event["maxAttempts"]
    delay_seconds = event.get("delaySecondsDefault", 120)

    # -------------------------------------------------
    # CASE 1: Cleanup Lambda failed and Catch was hit
    # -------------------------------------------------
    if "error" in event:
        error_type = event["error"]["Error"]

        if attempt < max_attempts and error_type in RETRYABLE_ERRORS:
            return {
                "action": "RETRY",
                "attempt": attempt + 1,
                "delaySeconds": delay_seconds,
                "reason": error_type
            }

        return {
            "action": "FAIL",
            "attempt": attempt,
            "reason": error_type
        }

    # -------------------------------------------------
    # CASE 2: Cleanup Lambda returned a response
    # -------------------------------------------------
    if "cleanupResult" not in event:
        return {
            "action": "FAIL",
            "attempt": attempt,
            "reason": "MissingCleanupResult"
        }

    cleanup_result = event["cleanupResult"]

    # Defensive: ensure dict
    if not isinstance(cleanup_result, dict):
        return {
            "action": "FAIL",
            "attempt": attempt,
            "reason": "InvalidCleanupResult"
        }

    status_code = cleanup_result.get("statusCode")

    # SUCCESS
    if status_code == 200:
        return {
            "action": "SUCCESS",
            "attempt": attempt
        }

    # RETRYABLE FAILURE
    if status_code in RETRYABLE_STATUS_CODES and attempt < max_attempts:
        return {
            "action": "RETRY",
            "attempt": attempt + 1,
            "delaySeconds": delay_seconds,
            "reason": f"HTTP_{status_code}"
        }

    # HARD FAIL
    return {
        "action": "FAIL",
        "attempt": attempt,
        "reason": f"HTTP_{status_code or 'UNKNOWN'}"
    }

