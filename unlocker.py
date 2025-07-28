import subprocess  # Used to run shell commands from Python
import sys         # Used to access command-line arguments

# Function to unlock a file on Windows by removing deny permissions and restoring inheritance
def unlock_file(file_path):
    try:
        # Removes deny permissions for 'Everyone' on the file
        subprocess.run(["icacls", file_path, "/remove:d", "Everyone"], check=True)
        # Re-enables inherited permissions (like from parent folders)
        subprocess.run(["icacls", file_path, "/inheritance:e"], check=True)
        print(f"🔓 Unlocked file: {file_path}")
    except Exception as e:
        # Catch any errors and print them out
        print(f"⚠️ Failed to unlock file: {e}")

# Main block to run the function when the script is executed directly
if __name__ == "__main__":
    # Check if exactly one argument (file path) was provided
    if len(sys.argv) != 2:
        print("Usage: python unlocker.py <file_path>")  # Instructions for the poor lost soul
    else:
        unlock_file(sys.argv[1])  # Call the unlock function with the provided file path
