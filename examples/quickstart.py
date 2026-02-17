"""AgentGuard Quickstart — protect any function in 2 lines of code."""

from pathlib import Path

from agentguard import Guard, protect

POLICY_PATH = Path(__file__).parent / "demo_policy.yaml"

guard = Guard(policy=POLICY_PATH)


@protect(guard=guard)
def delete_user(user_id: str) -> str:
    """Simulate deleting a user from the database."""
    return f"User {user_id} deleted"  # This would be a real DB call


@protect(guard=guard)
def search_users(query: str) -> str:
    """Simulate searching users."""
    return f"Found users matching: {query}"


if __name__ == "__main__":
    # This will be ALLOWED (matches "search_*" / "*_search" pattern)
    result = search_users(query="active users")
    print(f"ALLOWED: {result}")

    # This will be BLOCKED (matches "delete_*" deny rule)
    try:
        print(delete_user(user_id="123"))
    except Exception as e:
        print(f"BLOCKED: {e}")
