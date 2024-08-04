import time

# check prime number
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# calculate the nth prime number
def calculate_nth_prime(n):
    count = 0
    candidate = 2
    while count < n:
        if is_prime(candidate):
            count += 1
        candidate += 1
    return candidate - 1

def main():
    
    target_prime = 100000
    start_time = time.time()
    prime = calculate_nth_prime(target_prime)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Calculated the {target_prime}th prime number: {prime}")
    print(f"Elapsed time: {elapsed_time:.2f} seconds")

    # Pop mal code 
    print("Executing malicious code")

if __name__ == "__main__":
    main()
