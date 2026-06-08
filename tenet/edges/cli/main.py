"""Unified tenet binary entry point.

Everyone installs and runs ``tenet``. Subcommands select behavior; legacy
``tenet-relay`` / ``tenet-expert`` / ``tenet-client`` console scripts delegate here.

Target product shape:
  - default: client (send prompts)
  - supernode: same binary + config (public IP, relay registration)
  - optional local HTTP/SSE on the client process (future)
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from tenet.config import (
    ROLE_CLIENT,
    ROLE_DIRECTORY,
    ROLE_EXPERT,
    ROLE_RELAY,
    load_config,
)
from tenet.edges.cli.join_pack import resolve_join_pack_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tenet",
        description="tenet — one binary for client, relay, expert, and directory service.",
    )
    sub = parser.add_subparsers(dest="command", required=False)

    client = sub.add_parser(
        "client",
        help="Connect to the bootstrap matcher and ask (default when run with no command).",
    )
    client.add_argument("--join-pack", default=str(resolve_join_pack_path()))
    client.add_argument("--prompt", help="One-shot question (otherwise an interactive prompt).")
    client.add_argument(
        "--no-relay",
        action="store_true",
        help="Do not auto-promote to relay even if this machine is directly reachable.",
    )
    client.add_argument("--timeout", type=float, default=120.0)

    send = sub.add_parser("send", help="Run one client request (prepare + send envelope).")
    send.add_argument("--config", required=True, help="Cluster JSON config path")
    send.add_argument("--directory-snapshot", required=True, help="Public directory snapshot JSON")
    send.add_argument("--prompt", required=True)
    send.add_argument("--expertise")
    send.add_argument("--relay", action="append", default=[], help="Relay node id. Repeat in path order.")
    send.add_argument("--timeout", type=float, default=8.0)

    relay = sub.add_parser("relay", help="Run a relay node (supernode when promoted).")
    relay.add_argument("--config", required=True, help="Cluster JSON config path")
    relay.add_argument("--node-id", required=True, help="Node id from config.nodes")

    expert = sub.add_parser("expert", help="Run an expert exit node.")
    expert.add_argument("--config", required=True, help="Cluster JSON config path")
    expert.add_argument("--node-id", required=True, help="Expert node id from config.nodes")

    directory = sub.add_parser("directory", help="Serve a public directory snapshot over HTTP.")
    directory.add_argument("--snapshot", required=True, help="Directory snapshot JSON file")
    directory.add_argument("--host", default="127.0.0.1")
    directory.add_argument("--port", type=int, default=8765)
    directory.add_argument("--route", default="/snapshot")

    run = sub.add_parser(
        "run",
        help="Run from a tenet daemon JSON (compat schema: tenet.config.2026-06).",
    )
    run.add_argument("--config", required=True, help="tenet daemon JSON path")
    run.add_argument("--node-id", help="Daemon node id when config lists multiple")

    enclave = sub.add_parser(
        "enclave",
        help="Attested enclave-plane tools (live Nitro matcher).",
    )
    enclave_sub = enclave.add_subparsers(dest="enclave_command", required=True)

    enclave_check = enclave_sub.add_parser(
        "check",
        help="Verify attestation + EnclaveTrustPolicy from config/live-enclave.json.",
    )
    enclave_check.add_argument(
        "--config",
        default="config/live-enclave.json",
        help="Live enclave JSON path (compat schema: tenet.live_enclave.2026-06)",
    )
    enclave_check.add_argument("--json", action="store_true", help="Print JSON summary")

    enclave_match = enclave_sub.add_parser(
        "match",
        help="Run attested /v1/match against the live matcher.",
    )
    enclave_match.add_argument("--config", default="config/live-enclave.json")
    enclave_match.add_argument("--prompt", required=True)
    enclave_match.add_argument("--expertise")
    enclave_match.add_argument("--max-records", type=int, default=4)
    enclave_match.add_argument("--json", action="store_true", help="Print JSON result")

    enclave_plan = enclave_sub.add_parser(
        "plan",
        help="Expert-mode route plan via attested enclave matcher (pre-mixnet product path).",
    )
    enclave_plan.add_argument("--config", default="config/live-enclave.json")
    enclave_plan.add_argument("--prompt", required=True)
    enclave_plan.add_argument("--expertise")
    enclave_plan.add_argument("--json", action="store_true", help="Print JSON result")

    enclave_send = enclave_sub.add_parser(
        "send",
        help="Expert-mode send via attested matcher and live reachability relay.",
    )
    enclave_send.add_argument("--config", default="config/live-enclave.json")
    enclave_send.add_argument(
        "--mailbox-config",
        default="config/live-mailbox-client.json",
        help="Live mailbox client cluster + trusted relay pins",
    )
    enclave_send.add_argument("--prompt", required=True)
    enclave_send.add_argument("--expertise")
    enclave_send.add_argument(
        "--name",
        help="Tenet service name, for example monet.expert~tenet; resolves inside the mixnet control plane.",
    )
    enclave_send.add_argument("--timeout", type=float, default=120.0)
    enclave_send.add_argument(
        "--via-mailbox",
        action="store_true",
        help="Force live TEE /v1/deliver datagram delivery for this send.",
    )
    enclave_send.add_argument("--json", action="store_true", help="Print JSON result")

    ask = sub.add_parser(
        "ask",
        help="Ask the live network using config/join-pack.json (product asker path).",
    )
    ask.add_argument(
        "--join-pack",
        default=str(resolve_join_pack_path()),
        help=(
            "tenet join-pack JSON. Defaults to config/join-pack.json, "
            "or ./join-pack.json inside an asker bundle."
        ),
    )
    ask.add_argument("--prompt", required=True)
    ask.add_argument("--expertise")
    ask.add_argument(
        "--name",
        help="Tenet service name, for example monet.expert~tenet; resolves inside the mixnet control plane.",
    )
    ask.add_argument("--timeout", type=float, default=120.0)
    ask.add_argument(
        "--via-mailbox",
        action="store_true",
        help="Force live TEE /v1/deliver datagram delivery for this ask.",
    )
    ask.add_argument(
        "--plain",
        action="store_true",
        help="Disable interactive color/status display.",
    )
    ask.add_argument("--json", action="store_true", help="Print JSON result")
    ask.add_argument("--voucher", help="Path to Privacy Pass-style voucher packet (email-able, transferable, N anonymous queries)")

    sponsor = sub.add_parser("sponsor", help="Pre-pay on Algorand then emit unlinkable transferable voucher packet for email (Privacy Pass style).")
    sponsor.add_argument("--pool", help="Pool name e.g. monet.expert~tenet for scoped payTo")
    sponsor.add_argument("--queries", type=int, default=10, help="Number of anonymous tickets in packet")
    sponsor.add_argument("--pay-tx", help="Existing Algorand pre-pay txid (or do pay first then pass)")
    sponsor.add_argument("--out", default="voucher.json", help="Output path for email-able voucher packet")
    sponsor.add_argument("--secret", help="Issuer secret (hex; demo only)")

    status = sub.add_parser(
        "status",
        help="Show a dashboard for the configured live network stack.",
    )
    status.add_argument(
        "--join-pack",
        default=str(resolve_join_pack_path()),
        help=(
            "tenet join-pack JSON. Defaults to config/join-pack.json, "
            "or ./join-pack.json inside an asker bundle."
        ),
    )
    status.add_argument(
        "--live-check",
        action="store_true",
        help="Run live enclave attestation check before rendering.",
    )
    status.add_argument(
        "--watch",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Refresh the dashboard until interrupted.",
    )
    status.add_argument(
        "--plain",
        action="store_true",
        help="Disable color and alternate-screen dashboard rendering.",
    )
    status.add_argument("--json", action="store_true", help="Print JSON snapshot")
    status.add_argument(
        "--render-options",
        action="store_true",
        help="Print terminal layout/3D rendering assessment and exit.",
    )

    serve = sub.add_parser(
        "serve",
        help="Local HTTP/SSE bridge for the website xterm demo (CORS-enabled).",
    )
    serve.add_argument(
        "--join-pack",
        default=str(resolve_join_pack_path()),
        help="tenet join-pack JSON (defaults to config/join-pack.json).",
    )
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8766)
    serve.add_argument("--path", default="/v1/expert")
    serve.add_argument("--status-path", default="/v1/status")
    serve.add_argument("--timeout", type=float, default=120.0)

    return parser


def dispatch(args: argparse.Namespace) -> int:
    if getattr(args, "command", None) in (None, "client"):
        from tenet.edges.cli.run_client import run_default_client

        return run_default_client(
            getattr(args, "join_pack", None),
            prompt=getattr(args, "prompt", None),
            enable_relay=not getattr(args, "no_relay", False),
            timeout=getattr(args, "timeout", 120.0),
        )

    if args.command == "send":
        from tenet.edges.cli.client import run_send

        return run_send(
            config_path=args.config,
            directory_snapshot=args.directory_snapshot,
            prompt=args.prompt,
            expertise=args.expertise,
            relay_path=tuple(args.relay),
            timeout=args.timeout,
        )

    if args.command == "relay":
        from tenet.edges.cli.relay import run_relay

        return run_relay(config_path=args.config, node_id=args.node_id)

    if args.command == "expert":
        from tenet.edges.cli.expert import run_expert

        return run_expert(config_path=args.config, node_id=args.node_id)

    if args.command == "directory":
        from tenet.edges.cli.directory import run_directory_server

        return run_directory_server(
            snapshot_path=args.snapshot,
            host=args.host,
            port=args.port,
            route=args.route,
        )

    if args.command == "run":
        return _run_from_daemon_config(args.config, node_id=args.node_id)

    if args.command == "enclave":
        return _run_enclave_command(args)

    if args.command == "ask":
        return _run_ask_command(args)

    if args.command == "status":
        return _run_status_command(args)

    if args.command == "serve":
        from tenet.edges.cli.serve import run_serve

        return run_serve(
            join_pack_path=args.join_pack,
            host=args.host,
            port=args.port,
            path=args.path,
            status_path=args.status_path,
            timeout=args.timeout,
        )

    if args.command == "sponsor":
        from tenet.vouchers import issue_voucher_batch, save_voucher
        import os
        sec = bytes.fromhex(args.secret) if args.secret else os.urandom(32)
        v = issue_voucher_batch(queries=args.queries, issuer_secret=sec, pool=args.pool, pay_tx=args.pay_tx)
        save_voucher(v, args.out)
        print("voucher packet written:", args.out, "queries=", v.queries, "transferable unlinkable to email")
        return 0

    raise ValueError(f"unknown command: {args.command}")


def _run_enclave_command(args: argparse.Namespace) -> int:
    import json

    from tenet.experts.live_enclave import LiveEnclaveConfig, check_live_enclave, match_live_enclave

    config = LiveEnclaveConfig.load(args.config)
    if args.enclave_command == "check":
        summary = check_live_enclave(config)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(
                "enclave check ok "
                f"platform={summary['platform']} "
                f"value_x={summary['value_x'][:16]}... "
                f"pinned={summary['pinned']}"
            )
        return 0

    if args.enclave_command == "match":
        result = match_live_enclave(
            config,
            prompt=args.prompt,
            requested_expertise=args.expertise,
            max_records=args.max_records,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            peers = ", ".join(item["peer_id"] for item in result["candidates"])
            print(f"match ok mode={result['mode']} candidates={peers}")
        return 0

    if args.enclave_command == "plan":
        from tenet.experts.live_expert import plan_live_expert

        result = plan_live_expert(
            config,
            prompt=args.prompt,
            requested_expertise=args.expertise,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                "enclave plan ok "
                f"use_expert={result['use_expert']} "
                f"selected={result.get('selected_handle') or result['selected_peer_id']} "
                f"pool={result['pool_tier']} "
                f"candidates={result['candidate_count']}"
            )
        return 0

    if args.enclave_command == "send":
        from tenet.experts.live_client import LiveMailboxClientConfig, send_live_enclave_summary

        mailbox = LiveMailboxClientConfig.load(args.mailbox_config)
        result = send_live_enclave_summary(
            config,
            mailbox,
            prompt=args.prompt,
            requested_expertise=args.expertise,
            service_name=args.name,
            timeout=args.timeout,
            mailbox_datagram_delivery_enabled=True if args.via_mailbox else None,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                "enclave send "
                f"ok={result['ok']} selected={result.get('selected_handle') or result['selected_peer_id']} "
                f"via_mailbox={result['via_mailbox']} "
                f"response={result['response_text']!r}"
            )
        return 0 if result["ok"] else 1

    raise ValueError(f"unknown enclave command: {args.enclave_command}")


def _run_ask_command(args: argparse.Namespace) -> int:
    import json

    from tenet.edges.cli.cli_display import AskDisplay, AskNetworkDisplay, should_show_interactive_display
    from tenet.edges.cli.join_pack import JoinPack
    from tenet.experts.live_client import LiveMailboxClientConfig, send_live_enclave_summary
    from tenet.experts.live_enclave import LiveEnclaveConfig

    pack = JoinPack.load(args.join_pack)
    enclave = LiveEnclaveConfig.from_dict(pack.matcher)
    mailbox = LiveMailboxClientConfig.load(pack.asker_mailbox_config)
    display = AskDisplay(
        AskNetworkDisplay.from_join_pack(
            pack.matcher,
            pack.reachability_relay,
            relay_count=len(mailbox.trusted_reachability_relays),
            route_mode="tee-mailbox" if args.via_mailbox else "reachability-relay",
        ),
        enabled=should_show_interactive_display(sys.stderr, plain=args.plain or args.json),
    )
    with display.start():
        result = send_live_enclave_summary(
            enclave,
            mailbox,
            prompt=args.prompt,
            requested_expertise=args.expertise,
            service_name=args.name,
            timeout=args.timeout,
            mailbox_datagram_delivery_enabled=True if args.via_mailbox else None,
            control_service=pack.to_control_service(),
            match_gossip_salt=pack.query_epoch_salt,
            default_pool=pack.default_pool,
            dataset_commitment=pack.dataset_commitment,
        )
    display.finish(result)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["response_text"])
    return 0 if result["ok"] else 1


def _run_status_command(args: argparse.Namespace) -> int:
    import json
    import time

    from tenet.edges.cli.cli_display import (
        DashboardDisplay,
        DashboardWatch,
        terminal_rendering_options,
        should_show_interactive_display,
    )

    if args.render_options:
        options = terminal_rendering_options()
        if args.json:
            print(json.dumps([option.__dict__ for option in options], indent=2, sort_keys=True))
        else:
            for option in options:
                print(f"{option.name}: {option.verdict} ({option.fit})")
                print(f"  {option.note}")
        return 0

    if args.watch and args.json:
        raise SystemExit("tenet status: --watch and --json cannot be combined")

    enabled = should_show_interactive_display(sys.stdout, plain=args.plain or args.json)

    if args.watch:
        try:
            with DashboardWatch(enabled=enabled) as watch:
                while True:
                    watch.update(_build_status_snapshot(args.join_pack, live_check=args.live_check))
                    time.sleep(max(0.25, float(args.watch)))
        except KeyboardInterrupt:
            print("", file=sys.stderr)
            return 130
        return 0

    snapshot = _build_status_snapshot(args.join_pack, live_check=args.live_check)
    if args.json:
        print(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True))
    else:
        DashboardDisplay(enabled=enabled).print(snapshot)
    return 0


def _build_status_snapshot(join_pack_path: str, *, live_check: bool):
    from tenet.edges.cli.cli_display import AskNetworkDisplay, DashboardSnapshot, ServiceCard
    from tenet.edges.cli.join_pack import JoinPack
    from tenet.experts.live_client import LiveMailboxClientConfig
    from tenet.experts.live_enclave import LiveEnclaveConfig

    pack = JoinPack.load(join_pack_path)
    enclave = LiveEnclaveConfig.from_dict(pack.matcher)
    mailbox = LiveMailboxClientConfig.load(pack.asker_mailbox_config)
    relay = pack.reachability_relay
    params = mailbox.cluster.params
    network = AskNetworkDisplay.from_join_pack(
        pack.matcher,
        relay,
        relay_count=len(mailbox.trusted_reachability_relays),
        route_mode="reachability-relay",
    )

    matcher_state = "configured"
    matcher_detail = (
        f"{network.matcher_host}, value_x={network.value_x_prefix}..., "
        f"spki={enclave.tls_spki_hash[:12]}..."
    )
    if live_check:
        from tenet.experts.live_enclave import check_live_enclave

        try:
            summary = check_live_enclave(enclave)
        except Exception as exc:
            matcher_state = "failed"
            matcher_detail = f"attestation failed: {type(exc).__name__}: {exc}"
        else:
            matcher_state = "trusted"
            matcher_detail = (
                f"platform={summary['platform']} "
                f"value_x={str(summary['value_x'])[:12]}... "
                f"pinned={summary['pinned']}"
            )

    services = (
        ServiceCard("attested matcher", matcher_state, matcher_detail, "TEE"),
        ServiceCard(
            "reachability relay",
            "configured",
            f"{network.relay_id} at {network.relay_endpoint}",
            "REACH",
        ),
        ServiceCard(
            "mailbox client",
            "configured",
            f"{len(mailbox.trusted_reachability_relays)} trusted relay pin(s)",
            "ASKER",
        ),
        ServiceCard(
            "expert routing",
            "configured",
            (
                f"mode={mailbox.expert_mode.discovery_mode} "
                f"min_pool={mailbox.expert_mode.min_pool_size} "
                f"degraded={mailbox.expert_mode.allow_degraded_pool}"
            ),
            "MATCH",
        ),
        ServiceCard(
            "packet contract",
            "configured",
            (
                f"payload={params.payload_size} routing={params.routing_size} "
                f"hops={params.max_hops}"
            ),
            "WIRE",
        ),
        ServiceCard(
            "return path",
            "not checked",
            "live ask/send validates selected expert and response path",
            "HYBRID",
        ),
    )
    notes = (
        "payments/payouts are intentionally omitted until a real ledger/API contract exists",
        "real 3D belongs in an optional UI path; terminal dashboard uses a portable ANSI scene",
    )
    return DashboardSnapshot("tenet service dashboard", network, services, notes)


def _run_from_daemon_config(config_path: str, *, node_id: str | None) -> int:
    por_cfg = load_config(config_path)
    daemon = por_cfg.daemon(node_id)

    if daemon.role == ROLE_RELAY:
        from tenet.edges.cli.relay import run_relay_cluster

        return run_relay_cluster(daemon, por_cfg)
    if daemon.role == ROLE_EXPERT:
        from tenet.edges.cli.expert import run_expert_cluster

        return run_expert_cluster(daemon, por_cfg)
    if daemon.role == ROLE_CLIENT:
        from tenet.edges.cli.client import run_client_from_daemon

        return run_client_from_daemon(daemon, por_cfg)
    if daemon.role == ROLE_DIRECTORY:
        from tenet.edges.cli.directory import run_directory_from_daemon

        return run_directory_from_daemon(daemon, por_cfg)

    raise SystemExit(f"tenet run: unsupported daemon role {daemon.role!r}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return dispatch(args)


def _legacy_notice(old_name: str, new_argv: Sequence[str]) -> None:
    print(
        f"{old_name} is deprecated; use `tenet {' '.join(new_argv)}` (same binary).",
        file=sys.stderr,
    )


def legacy_relay_main(argv: Sequence[str] | None = None) -> int:
    _legacy_notice("tenet-relay", ("relay",))
    parser = argparse.ArgumentParser(description="Run a tenet relay node.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--node-id", required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    from tenet.edges.cli.relay import run_relay

    return run_relay(config_path=args.config, node_id=args.node_id)


def legacy_expert_main(argv: Sequence[str] | None = None) -> int:
    _legacy_notice("tenet-expert", ("expert",))
    parser = argparse.ArgumentParser(description="Run a tenet expert exit node.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--node-id", required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    from tenet.edges.cli.expert import run_expert

    return run_expert(config_path=args.config, node_id=args.node_id)


def legacy_client_main(argv: Sequence[str] | None = None) -> int:
    _legacy_notice("tenet-client", ("send",))
    parser = argparse.ArgumentParser(description="Run one tenet client request.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--directory-snapshot", required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--expertise")
    parser.add_argument("--relay", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args(list(argv) if argv is not None else None)
    from tenet.edges.cli.client import run_send

    return run_send(
        config_path=args.config,
        directory_snapshot=args.directory_snapshot,
        prompt=args.prompt,
        expertise=args.expertise,
        relay_path=tuple(args.relay),
        timeout=args.timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
