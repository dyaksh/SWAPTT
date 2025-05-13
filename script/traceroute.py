#!/usr/bin/env python3
import sys
import subprocess
import platform

def run_traceroute(target):
    """Run traceroute or tracert on the target and return the result as text."""
    if not target:
        return "Error: No target provided."
    
    system_os = platform.system()
    if system_os == "Windows":
        command = ["tracert", target]
    else:
        command = ["traceroute", target]

    try:
        # NO timeout added here
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0 and result.stdout:
            return result.stdout
        elif result.stderr:
            return f"Traceroute failed:\n{result.stderr}"
        else:
            return "Traceroute did not return any output."
    except Exception as e:
        return f"Error running traceroute: {str(e)}"

def main():
    if len(sys.argv) != 2:
        print("Usage: python traceroute.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    output = run_traceroute(target)
    print(output)

if __name__ == "__main__":
    main()
