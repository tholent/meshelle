# meshelle — open questions

A place for questions about this project's direction: ones still open, and ones
already investigated whose answer was *not yet, and here is why*. Each entry
records what was asked, what the investigation found, and what is still unknown —
so the next person does not repeat the research before reaching the same place.

**This is not the settled-decisions list.** Those live in `HANDOFF.md` §5 and are
not to be relitigated. Loose ends and optional work live in `HANDOFF.md` §12.

Adding an entry: state it as a question, date it, and give it a status line —
`Open` (not yet investigated), `Answered — deferred` (researched, decision made
to not act yet), or `Closed` (acted on; say where the work landed).

---

## Q1. Should meshelle drive a "dumb modem" firmware instead of the stock companion?

*Asked 2026-09-10. Status: **Answered — deferred.** No fork; revisit if the
triggers below fire.*

The original framing was whether to maintain a selective fork of MeshCore
producing a bare companion node driven by an outside process. **A fork is not
needed: upstream already ships one.**
`~/src/meshcore-refs/MeshCore/examples/kiss_modem/` is exactly that firmware. It
builds for all 84 variants (the same coverage as `companion_radio`) and is
specified in `docs/kiss_modem_protocol.md`.

### What it is

`examples/kiss_modem/main.cpp` links `mesh::Radio` directly — no `Dispatcher`, no
`Mesh`, no contact book, no message store. Standard KISS framing over USB/UART at
115200 8N1, with MeshCore extensions carried by the standard KISS `SetHardware`
(0x06) command.

| Direction | Mechanism | Citation |
|---|---|---|
| RX | raw packet as a KISS data frame, **then** `HW_RESP_RX_META` (0xF9) = `[snr*4][rssi]` | `KissModem.cpp:456` |
| TX | KISS data frame in; CSMA (p-persistence, slottime, `isReceiving`) then `startSendRaw`; `HW_RESP_TX_DONE` (0xF8) reports real success/failure | `KissModem.cpp:389-455` |
| Radio | host sets params: `HW_CMD_SET_RADIO`, `SET_TX_POWER`; reads `GET_CURRENT_RSSI`, `GET_NOISE_FLOOR`, `IS_CHANNEL_BUSY`, `GET_AIRTIME`, `GET_STATS`, `GET_BATTERY` | `KissModem.h:45-65` |

The node's identity is loaded from flash but used only for the HW crypto
sub-commands. It never transmits on its own initiative.

### What it would buy meshelle

1. **Trap #3 disappears.** `MAX_FRAME_SIZE 176` (`helpers/BaseSerialInterface.h:5`)
   is why `logRxRaw` silently skips any packet over 173 bytes
   (`companion_radio/MyMesh.cpp:287`). KISS carries the full `MAX_TRANS_UNIT` of
   255, so long-path flood packets stop being invisible to us.
2. **Trap #8 disappears.** No contact book means the node no longer auto-adds our
   own rooms as contacts, no `NEW_ADVERT`/`CONTACTS_FULL` pushes to ignore, and no
   flash write on every advert we transmit.
3. **Radio provisioning moves into `meshelle.toml`.** Today a headless Pi's node
   must first be provisioned by the phone app. With KISS, frequency, bandwidth,
   SF, CR and TX power are host configuration — a real win for the systemd target.
4. **`doctor` and `RadioStats` get measured numbers** — noise floor, current RSSI,
   channel-busy, packet counters — instead of inference.
5. **`TX_DONE` is a real confirmation.** `RESP_CODE_OK` after `CMD_SEND_RAW_PACKET`
   only means the packet parsed and was queued.

### What it would cost

- **Duty cycle becomes meshelle's problem.** `Dispatcher.cpp:280` enforces an
  airtime budget; the KISS modem does not — it does CSMA only. On EU868 that is a
  regulatory obligation moving into `mesh/scheduler.py`.
- **TX is one-at-a-time behind a 2-slot output queue.** A second data frame before
  `TxDone` is refused with `TxBusy` (0x07), so the send loop becomes TxDone-gated
  rather than `RESP_CODE_OK`-gated.
- **`transport/ble.py` is unusable on this path.** kiss_modem is serial/UART only.
- **`RX_META` arrives *after* its data frame**, so pairing SNR/RSSI with a packet
  needs explicit care; and `main.cpp:130` skips `recvRaw` entirely while
  transmitting or while host output is backed up — a documented RX-loss window.
- **The node becomes single-purpose.** It can no longer serve a phone app, stock
  tooling cannot talk to it, and the operator may have to build the firmware
  locally rather than use a prebuilt flasher image.
- **Wrong radio parameters look exactly like "no traffic."** A new failure mode
  that needs its own `doctor` check.

### The decision, and what would change it

Verify on real hardware against **stock companion firmware first**
(`HANDOFF.md` §11). That is the configuration operators actually have, and the one
thing §11 must prove — the ACL byte producing a compose box in the app — is
unaffected by which firmware is underneath.

Revisit if any of these fire:

- room traffic is observed being lost to the 173-byte RX ceiling;
- provisioning the node by phone app proves unworkable for headless deployment;
- measured radio telemetry becomes necessary to diagnose a real deployment.

If so, add KISS as a **second link implementation, not a fork**:

- `transport/kiss.py` for the framing (FEND/FESC escaping) and the HW sub-command
  codec;
- a `KissLink` exposing the same `send_packet` / `packets()` surface as
  `CompanionLink`, behind the seam `mesh/dispatcher.py:70` already uses — the
  dispatcher depends on a packet sink, not on `CompanionLink`;
- selected by config, e.g. `companion.protocol = "companion" | "kiss"`.

That leaves `proto/`, `room/`, `store/` and the entire test suite untouched.

### Still unanswered

- Where does the duty-cycle budget belong if KISS is ever adopted — `Scheduler`,
  or a new layer between it and the link? Nothing in meshelle tracks airtime today.
- Are prebuilt `kiss_modem` images published for the common boards, or does every
  operator need a PlatformIO toolchain? This decides whether it can ever be the
  documented default.
- Does the RX-loss window (`main.cpp:130`) matter at room traffic levels, or is it
  only a concern for a busy repeater? Measurable only on hardware.
