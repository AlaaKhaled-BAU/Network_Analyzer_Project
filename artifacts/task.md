# Task: Phase B — Detection Latency Reduction (15s → ~3s)

## Goal
Reduce NetGuardian Pro's end-to-end attack detection time from ~15–20 seconds to ~3 seconds by optimizing the sniffer buffer interval, sender poll rate, and — most critically — making predictions inline at ingestion time instead of relying on a 10-second background loop.

## Success Criteria
- [x] Sniffer saves packets every 2s instead of 5s
- [x] Sender polls every 0.5s instead of 1s
- [x] Server runs predictions inline in `_process_packets()` immediately after aggregation
- [x] Background prediction loop remains as fallback with 30s interval
- [x] End-to-end detection of a SYN flood occurs within ≤5 seconds
- [x] No regressions: existing dashboard, WebSocket, and Telegram alerts still work
- [x] CHANGES.md updated with all changes

## Execution Groups

**Group: Client-Side Latency** – Parallel – Claude Sonnet (standard coding, straightforward edits)
- [x] Reduce `SAVE_INTERVAL` from 5 → 2 seconds in `client/sniffer.py`
- [x] Reduce `POLL_INTERVAL` from 1 → 0.5 seconds in `client/sender.py`
- [x] Keep Scapy (it is NOT the bottleneck — the 15s latency is pipeline timing, not capture speed)
- [x] Verify sniffer still handles multi-interface threading correctly with faster saves

**Group: Server Inline Prediction** – Parallel – Claude Sonnet (reliable coding for critical path change)
- [x] Modify `_process_packets()` in `server/app/main.py` to call `predict_and_alert()` inline after aggregation
- [x] Change background `PREDICTION_INTERVAL` from 10s → 30s (fallback role only)
- [x] Ensure inline predictions don't break the `/ingest` response time (should still be <2s per batch)
- [x] Add `process_dataframe()` method to `MultiWindowAggregator.py` to skip temp CSV I/O
- [x] Update `_process_packets()` to use `process_dataframe()` instead of writing temp CSV

**Group: Integration Testing** – Sequential after both groups – Claude Sonnet (validation)
- [x] Start server, run sniffer + sender locally
- [x] Send test attack traffic (or use curl with test packets)
- [x] Measure end-to-end time from packet capture to Telegram alert / WebSocket broadcast
- [x] Verify dashboard WebSocket still receives live updates
- [x] Verify no duplicate predictions between inline and background fallback
- [x] Update CHANGES.md with all modifications

## Timeline Estimate
[0–30m] Both parallel groups execute simultaneously
[30–45m] Integration testing (after both groups complete)
Total estimated time: ~45m

## Risks / Creative Notes
- Risk: **LOW** | Inline prediction in `_process_packets()` could slow down the `/ingest` endpoint if XGBoost inference is heavy. Mitigation: XGBoost predict() is typically <10ms for single samples, well within acceptable range
- Risk: **LOW** | Reducing save interval to 2s means more frequent file writes. Mitigation: Already using atomic writes with `.ready` markers, more files but smaller = same total I/O
- Risk: **MEDIUM** | Duplicate predictions possible if inline predicts AND background loop picks up same features. Mitigation: the `predicted_label == None` filter in `run_predictions()` already guards against this — inline sets the label first
- Creative note: The temp CSV elimination (`process_dataframe()`) is a bonus optimization that removes ~50ms of file I/O per batch — small but free
