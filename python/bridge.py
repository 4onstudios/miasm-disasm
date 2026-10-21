"""Private, one-request JSON bridge. Embedded in the Rust executable at build time.

Miasm performs all binary parsing, instruction decoding, and CFG splitting.
The input executable is never launched or emulated.
"""

import contextlib
import json
import logging
import os
import sys
from collections import deque

PROTOCOL = 1
MAX_FILE_BYTES = 64 * 1024 * 1024


class BridgeError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def require(condition, message):
    if not condition:
        raise BridgeError("invalid_request", message)


def integer(request, name, default, minimum=0, maximum=(1 << 64) - 1):
    value = request.get(name, default)
    require(type(value) is int and minimum <= value <= maximum,
            f"{name} must be an integer between {minimum} and {maximum}")
    return value


def run(request):
    require(isinstance(request, dict), "request must be a JSON object")
    require(request.get("protocol") == PROTOCOL, "unsupported protocol version")
    try:
        import miasm
        from miasm.analysis.machine import Machine
        from miasm.analysis.binary import ContainerPE, ContainerELF, ContainerUnknown
        from miasm.core.locationdb import LocationDB
        from miasm.core.asmblock import AsmCFG, AsmBlockBad, AsmConstraint
    except ImportError as exc:
        raise BridgeError("missing_dependency", "Miasm could not be imported. Install python/requirements.txt "
                          "into a virtual environment and pass its interpreter with --python. "
                          f"Details: {exc}") from exc

    # Miasm's parser diagnostics belong on stderr, never in the JSON channel.
    logging.disable(logging.WARNING)
    version = str(getattr(miasm, "VERSION", "unknown"))
    architectures = sorted(Machine.available_machine())
    if request.get("operation") == "doctor":
        return {"protocol": PROTOCOL, "python_version": sys.version.split()[0],
                "miasm_version": version, "architectures": architectures}
    require(request.get("operation") == "disassemble", "unknown operation")
    path = request.get("path")
    require(isinstance(path, str) and path, "path is required")
    mode = request.get("mode", "cfg")
    require(mode in ("cfg", "linear"), "mode must be cfg or linear")
    max_blocks = integer(request, "max_blocks", 256, 1, 10000)
    max_instructions = integer(request, "max_instructions", 10000, 1, 100000)
    raw = request.get("raw", False)
    follow_calls = request.get("follow_calls", False)
    require(type(raw) is bool and type(follow_calls) is bool, "raw and follow_calls must be booleans")
    base = integer(request, "base", 0)
    require(raw or base == 0, "base is only valid with raw input")
    arch = request.get("arch")
    require(arch is None or arch in architectures, "unsupported architecture; use doctor to list names")
    if raw:
        require(arch is not None, "raw input requires an architecture")
    try:
        with open(path, "rb") as stream:
            require(os.path.isfile(path), "input must be a regular file")
            if os.fstat(stream.fileno()).st_size > MAX_FILE_BYTES:
                raise BridgeError("input_too_large", "input exceeds the 64 MiB file limit")
            data = stream.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise BridgeError("input_error", str(exc)) from exc
    require(0 < len(data) <= MAX_FILE_BYTES, "input must contain 1 byte to 64 MiB")
    require(base + len(data) <= 1 << 64, "raw address range overflows 64 bits")
    loc_db = LocationDB()
    try:
        if raw:
            container, fmt = ContainerUnknown(data, loc_db, addr=base), "raw"
        elif data.startswith(b"MZ"):
            container, fmt = ContainerPE(data, loc_db), "PE"
        elif data.startswith(b"\x7fELF"):
            container, fmt = ContainerELF(data, loc_db), "ELF"
        else:
            raise BridgeError("unsupported_format", "expected PE or ELF; use --raw --arch ARCH for raw machine code")
    except BridgeError:
        raise
    except Exception as exc:
        raise BridgeError("invalid_binary", f"cannot parse executable: {exc}") from exc

    arch = arch or container.arch
    require(arch in architectures, "could not detect architecture; specify --arch")
    machine = Machine(arch)
    require(machine.dis_engine is not None, f"{arch} has no disassembly engine in this Miasm build")
    engine = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    engine.follow_call = follow_calls
    entry = base if raw else container.entry_point
    start = integer(request, "start", entry) if request.get("start") is not None else entry
    if raw:
        require(base <= start < base + len(data), "start is outside the raw input address range")
    warnings = []
    truncated = False

    def instruction(item):
        return {"address": item.offset, "size": item.l, "bytes": bytes(item.b).hex(),
                "mnemonic": item.name, "text": item.to_string(loc_db)}

    def block_address(block):
        return loc_db.get_location_offset(block.loc_key)

    if mode == "linear":
        address = start
        instructions = []
        while len(instructions) < max_instructions:
            if raw and address >= base + len(data):
                break
            try:
                item = engine.arch.dis(container.bin_stream, engine.attrib, address)
            except Exception as exc:
                if not instructions:
                    raise BridgeError("decode_error", f"cannot decode at {address:#x}: {exc}") from exc
                warnings.append(f"linear scan stopped at {address:#x}: {exc}")
                break
            require(item.l > 0, "decoder returned a zero-length instruction")
            instructions.append(instruction(item))
            address += item.l
        if len(instructions) == max_instructions and (not raw or address < base + len(data)):
            truncated = True
        blocks = [{"address": start, "label": f"loc_{start:x}", "instructions": instructions,
                   "successors": [], "error": None}]
    else:
        cfg = AsmCFG(loc_db)
        pending, scheduled, visited = deque([start]), {start}, set()
        engine.dont_dis = visited
        remaining = max_instructions
        count = 0
        while pending:
            address = pending.popleft()
            if address in visited:
                continue
            if count >= max_blocks or remaining == 0:
                truncated = True
                break
            engine.lines_wd = remaining
            block = engine.dis_block(address)
            count += 1
            if isinstance(block, AsmBlockBad):
                warnings.append(f"unable to decode block at {address:#x} (Miasm error {block.errno})")
            else:
                visited.update(item.offset for item in block.lines)
                remaining -= len(block.lines)
                # Miasm's line watchdog omits a successor at a straight-line cutoff.
                # Preserve it explicitly so budget exhaustion is visible to callers.
                if remaining == 0 and block.lines and not block.lines[-1].breakflow():
                    last = block.lines[-1]
                    next_address = last.offset + last.l
                    block.add_cst(loc_db.get_or_create_offset_location(next_address), AsmConstraint.c_next)
            cfg.add_block(block)
            next_addresses = sorted({loc_db.get_location_offset(edge.loc_key) for edge in block.bto
                                     if loc_db.get_location_offset(edge.loc_key) is not None})
            for target in next_addresses:
                if target not in scheduled:
                    pending.append(target)
                    scheduled.add(target)
        engine.apply_splitting(cfg)
        blocks = []
        for block in sorted(cfg.blocks, key=block_address):
            address = block_address(block)
            error = f"Miasm error {block.errno}" if isinstance(block, AsmBlockBad) else None
            successors = [{"address": loc_db.get_location_offset(edge.loc_key), "kind": edge.c_t}
                          for edge in block.bto if loc_db.get_location_offset(edge.loc_key) is not None]
            successors.sort(key=lambda edge: (edge["address"], edge["kind"]))
            blocks.append({"address": address, "label": loc_db.pretty_str(block.loc_key),
                           "instructions": [instruction(item) for item in block.lines],
                           "successors": successors, "error": error})
        if not any(block["instructions"] for block in blocks):
            raise BridgeError("decode_error", f"no instruction could be decoded at {start:#x}")

    if truncated:
        warnings.append("analysis limit reached; output is partial")
    return {"protocol": PROTOCOL, "miasm_version": version, "format": fmt, "architecture": arch,
            "mode": mode, "entry_point": entry, "start_address": start, "truncated": truncated,
            "instruction_count": sum(len(block["instructions"]) for block in blocks),
            "blocks": blocks, "warnings": warnings}


def main():
    try:
        request = json.load(sys.stdin)
        with contextlib.redirect_stdout(sys.stderr):
            result = run(request)
        payload = {"ok": True, "result": result}
    except BridgeError as exc:
        payload = {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
    except Exception as exc:
        payload = {"ok": False, "error": {"code": "backend_error", "message": f"{type(exc).__name__}: {exc}"}}
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
