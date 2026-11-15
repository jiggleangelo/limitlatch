def runaway_refund_loop(refund):
    allowed = blocked = 0
    for number in range(1, 41):
        try:
            refund(f"ord_{number:04d}", 2500, "buyer@example.test")
            allowed += 1
        except Exception as exc:
            if exc.__class__.__name__ != "Blocked": raise
            blocked += 1
    return allowed, blocked
