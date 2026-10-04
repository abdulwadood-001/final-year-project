"""
HoneyBot-IoT — Device State Manager service (scope M1-FE-4)

* seeds the three device states in Redis (device:cctv / device:smartlock / device:sensor)
* every few seconds advances the simulation: sensor telemetry random walk,
  threshold-breach alarms, camera motion events, battery drain, auto re-lock
* writes its own heartbeat so the dashboard Device Status Monitor sees it
All protocol honeypots read and write the same Redis hashes, so the device
looks identical whichever protocol the attacker uses.
"""

import os
import sys
import time
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.state import STATE, start_heartbeat, redis_client

INTERVAL = float(os.environ.get("STATE_TICK_SECONDS", 5))

logging.basicConfig(level=logging.INFO, format="%(asctime)s | state | %(message)s")
log = logging.getLogger("state")


def main():
    for _ in range(30):
        if redis_client():
            break
        time.sleep(2)
    STATE.init_defaults()
    start_heartbeat("device_state", interval=10)
    log.info("Device State Manager running (tick %.1fs)", INTERVAL)
    last_alarm = None
    while True:
        try:
            STATE.tick()
            alarm = STATE.field("sensor", "alarm")
            if alarm != last_alarm and alarm != "none":
                log.info("sensor alarm raised: %s (temp=%s)", alarm, STATE.field("sensor", "temperature"))
            last_alarm = alarm
        except Exception as e:
            log.error("tick failed: %s", e)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
