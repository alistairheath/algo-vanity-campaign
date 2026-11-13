# generate_mp.py
from multiprocessing import Process, Event, Manager, Value
import multiprocessing
import time
import os
from algosdk import account, mnemonic

# Desired prefix for address.
PREFIX = "ALGOX"

# How often each worker flushes its local counters to the shared counters.
UPDATE_BATCH = 1000

def worker(prefix, found_event, result_dict, attempts, small_matches, update_batch):
    """
    Worker loop: generate accounts until someone finds a match or the found_event is set.
    Each worker keeps local counters and flushes them periodically to the shared Value counters
    to reduce locking overhead.
    """
    local_attempts = 0
    local_small = 0

    while not found_event.is_set():
        PRIVATE_KEY, ADDRESS = account.generate_account()
        local_attempts += 1

        if ADDRESS.startswith(prefix):
            # Found! publish result and signal other processes to stop.
            result_dict['PRIVATE_KEY'] = PRIVATE_KEY
            result_dict['ADDRESS'] = ADDRESS
            found_event.set()
            break

        # periodically update shared counters to avoid a lock on every iteration
        if local_attempts >= update_batch:
            with attempts.get_lock():
                attempts.value += local_attempts
            if local_small:
                with small_matches.get_lock():
                    small_matches.value += local_small
            local_attempts = 0
            local_small = 0

    # flush remaining local counters before exit
    if local_attempts:
        with attempts.get_lock():
            attempts.value += local_attempts
    if local_small:
        with small_matches.get_lock():
            small_matches.value += local_small


def main(prefix=PREFIX, num_workers=None, update_batch=UPDATE_BATCH):
    if num_workers is None:
        num_workers = os.cpu_count() or 2

    print(f"Starting {num_workers} worker(s) to search for addresses starting with '{prefix}'")

    manager = Manager()
    result_dict = manager.dict()

    found_event = Event()
    attempts = Value('Q', 0)       # unsigned long long for total attempts
    small_matches = Value('Q', 0)  # count of SMALL_PREFIX matches

    workers = []
    start_time = time.time()

    try:
        for i in range(num_workers):
            p = Process(target=worker, args=(prefix, found_event,
                                             result_dict, attempts, small_matches, update_batch))
            p.start()
            workers.append(p)

        # main loop prints a live status line
        last_print = 0
        while not found_event.is_set():
            time.sleep(0.5)
            now = time.time()
            elapsed = now - start_time
            with attempts.get_lock():
                total = attempts.value
            with small_matches.get_lock():
                small = small_matches.value

            # show attempts/sec and totals, update every 0.5s
            if now - last_print >= 0.5:
                rate = total / elapsed if elapsed > 0 else 0
                print(f"\rAttempts: {total}  ({rate:.2f}/sec)", end="")
                last_print = now

        # found_event is set -> read result
        elapsed = time.time() - start_time
        # Ensure the latest counts are read (workers flush on exit)
        with attempts.get_lock():
            total = attempts.value
        with small_matches.get_lock():
            small = small_matches.value

        print()  # newline after status
        print(f"Found after approx {total} attempts and {elapsed:.2f} seconds")
        ADDRESS = result_dict.get('ADDRESS')
        PRIVATE_KEY = result_dict.get('PRIVATE_KEY')
        if ADDRESS and PRIVATE_KEY:
            print(ADDRESS)
            print(PRIVATE_KEY)
            print(mnemonic.from_private_key(PRIVATE_KEY))
        else:
            print("Signaller set but result not found in manager dict (race?)")

    except KeyboardInterrupt:
        print("\nKeyboardInterrupt — stopping workers...")
        found_event.set()
    finally:
        # Make sure all processes exit cleanly
        for p in workers:
            p.join(timeout=1)
            if p.is_alive():
                p.terminate()
        print("All workers stopped.")


if __name__ == "__main__":
    # On Windows the multiprocessing module requires the guard.
    # You can override workers or batch size using environment variables or editing call here.
    main()