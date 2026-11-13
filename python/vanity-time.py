#!/usr/bin/env python3
import sys
import math

def estimate_time(speed_per_second: float, prefix_length: int):
    """Estimate average time to find a prefix of given length at given speed."""
    total_possibilities = 32 ** prefix_length
    expected_seconds = total_possibilities / speed_per_second
    return expected_seconds, total_possibilities

def human_readable(seconds: float):
    """Convert seconds to a readable days/hours/minutes/seconds string."""
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    parts = []
    if days >= 1:
        parts.append(f"{int(days)}d")
    if hours >= 1:
        parts.append(f"{int(hours)}h")
    if minutes >= 1:
        parts.append(f"{int(minutes)}m")
    parts.append(f"{seconds:.1f}s")
    return " ".join(parts)

def probability_found(speed_per_second: float, prefix_length: int, hours: float):
    """Return probability of finding at least one match after a given number of hours."""
    p = 1 / (32 ** prefix_length)
    attempts = speed_per_second * hours * 3600
    # Probability = 1 - (1 - p)^attempts ≈ 1 - exp(-p*attempts)
    prob = 1 - math.exp(-p * attempts)
    return prob

def main():
    if len(sys.argv) not in (3, 4):
        print("Usage: python3 vanity_time.py <speed_per_second> <prefix_length> [hours_elapsed]")
        print("Example 1 (average time): python3 vanity_time.py 106776.54 7")
        print("Example 2 (probability):  python3 vanity_time.py 106776.54 7 20")
        sys.exit(1)

    speed = float(sys.argv[1])
    prefix_len = int(sys.argv[2])

    expected_seconds, total_possibilities = estimate_time(speed, prefix_len)
    readable = human_readable(expected_seconds)

    print(f"\n=== Vanity Address Time Estimate ===")
    print(f"Speed: {speed:,.2f} addresses/second")
    print(f"Prefix length: {prefix_len}")
    print(f"Expected attempts: {total_possibilities:,}")
    print(f"Average time (mean): {expected_seconds:,.2f} s (~{readable})")

    if len(sys.argv) == 4:
        hours = float(sys.argv[3])
        prob = probability_found(speed, prefix_len, hours)
        print(f"\nAfter {hours:.1f} hours at {speed:,.0f}/s,")
        print(f"chance of having found a match ≈ {prob*100:.2f}%")

    print("⚠️ Note: actual time varies — probability follows a geometric distribution.\n")

if __name__ == "__main__":
    main()