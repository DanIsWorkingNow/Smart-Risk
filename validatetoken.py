from huggingface_hub import HfApi, HfFolder
from huggingface_hub.utils import HfAuthenticationError


# Load the token from the cache or specify it directly
token = HfFolder.get_token()  # Retrieves the token from the cache
# Alternatively, specify your token directly:
# token = "your_huggingface_token"

api = HfApi()

try:
    user_info = api.whoami(token=token)
    print(f"Token is valid. Logged in as: {user_info['name']}")
except HfAuthenticationError:
    print("Invalid token. Please check your token and try again.")
