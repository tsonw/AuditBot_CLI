from engines.capture_services.packet_capture import PacketCaptureService
from scanners.network import get_local_network

DEFAULT_CAPTURE_DURATION_SECONDS = 60


def start_capture(duration_seconds: int = DEFAULT_CAPTURE_DURATION_SECONDS, interface: str | None = None):
       capture_interface = interface or get_local_network()["interface"]
       return PacketCaptureService().capture(capture_interface, duration_seconds)
