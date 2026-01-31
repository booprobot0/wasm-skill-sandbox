"""
EXAMPLE SAFE SKILL - For testing the scanner
This is a benign skill that should pass security scanning.
"""

def calculate_fibonacci(n: int) -> list:
    """Calculate first n Fibonacci numbers"""
    if n <= 0:
        return []
    if n == 1:
        return [0]

    fib = [0, 1]
    for i in range(2, n):
        fib.append(fib[i-1] + fib[i-2])
    return fib


def run():
    """Main entry point"""
    result = calculate_fibonacci(10)
    return f"Fibonacci sequence: {result}"
