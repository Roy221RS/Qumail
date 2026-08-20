import os
from kmAdapter import MockKMAdapter, NUM_KEYS, KEY_SIZE_BYTES

SENDER_PATH = "test_sender_bank.json"
RECEIVER_PATH = "test_receiver_bank.json"


def cleanup():
    for p in (SENDER_PATH, RECEIVER_PATH):
        if os.path.exists(p):
            os.remove(p)


def main():
    cleanup()  # start clean each run

    print("=" * 60)
    print("TEST 1: Basic bank generation")
    print("=" * 60)
    sender_km = MockKMAdapter(path=SENDER_PATH)
    status = sender_km.get_status()
    print(f"Status: {status}")
    assert status["total_keys"] == NUM_KEYS, "Wrong total key count!"
    assert status["available_keys"] == NUM_KEYS, "Should start fully available!"
    print(f"PASS - bank has {NUM_KEYS} keys, all available\n")

    print("=" * 60)
    print("TEST 2: Sender/receiver key sync (the important one)")
    print("=" * 60)
    print("Simulating two DIFFERENT machines - separate files, same seed.")
    receiver_km = MockKMAdapter(path=RECEIVER_PATH)

    key_bytes_sender, key_id = sender_km.get_key()
    print(f"Sender allocated key_id={key_id}, {len(key_bytes_sender)} bytes")

    key_bytes_receiver, echoed_id = receiver_km.get_key(key_id=key_id)
    print(f"Receiver fetched key_id={echoed_id}, {len(key_bytes_receiver)} bytes")

    assert key_id == echoed_id, "Key ID mismatch!"
    assert key_bytes_sender == key_bytes_receiver, "KEY BYTES DON'T MATCH - sync is broken!"
    assert len(key_bytes_sender) == KEY_SIZE_BYTES, "Wrong key size!"
    print("PASS - sender and receiver independently derived the SAME key bytes\n")

    print("=" * 60)
    print("TEST 3: Status updates after key use")
    print("=" * 60)
    status = sender_km.get_status()
    print(f"Sender status after 1 allocation: {status}")
    assert status["used_keys"] == 1
    assert status["available_keys"] == NUM_KEYS - 1
    print("PASS\n")

    print("=" * 60)
    print("TEST 4: Unknown key_id raises an error")
    print("=" * 60)
    try:
        receiver_km.get_key(key_id="KEY-9999")
        print("FAIL - should have raised KeyError!")
    except KeyError as e:
        print(f"PASS - correctly raised KeyError: {e}\n")

    print("=" * 60)
    print("TEST 5: Exhaustion handling (small bank for speed)")
    print("=" * 60)
    tiny_path = "test_tiny_bank.json"
    if os.path.exists(tiny_path):
        os.remove(tiny_path)
    tiny_km = MockKMAdapter(path=tiny_path, num_keys=3, key_size=16)
    for i in range(3):
        _, kid = tiny_km.get_key()
        print(f"  allocated {kid}")
    try:
        tiny_km.get_key()
        print("FAIL - should have raised RuntimeError!")
    except RuntimeError as e:
        print(f"PASS - correctly raised RuntimeError: {e}\n")
    os.remove(tiny_path)

    print("=" * 60)
    print("TEST 6: Persistence across restarts")
    print("=" * 60)
    sender_km_reloaded = MockKMAdapter(path=SENDER_PATH)
    status = sender_km_reloaded.get_status()
    print(f"Reloaded sender bank status: {status}")
    assert status["used_keys"] == 1, "Used state should have persisted to disk!"
    print("PASS - used key state survived a fresh instance on the same file\n")

    cleanup()
    print("=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
