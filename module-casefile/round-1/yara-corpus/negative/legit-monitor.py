"""Benign example: local Xlib key-event listener used by an accessibility tool.
Imports Xlib and reads keysyms, but posts nothing off-box — everything stays
local. A rule that hits 'Xlib + KeyPress' alone would misclassify this."""
from Xlib import display, X
from Xlib.ext import record
from Xlib.protocol import rq


def main():
    local_dpy = display.Display()
    record_dpy = display.Display()

    def handler(reply):
        if reply.category != record.FromServer:
            return
        data = reply.data
        while len(data):
            event, data = rq.EventField(None).parse_binary_value(data, record_dpy.display, None, None)
            if event.type == X.KeyPress:
                keysym = local_dpy.keycode_to_keysym(event.detail, 0)
                print(f"key: {keysym}")

    ctx = record_dpy.record_create_context(
        0, [record.AllClients],
        [{
            "core_requests": (0, 0), "core_replies": (0, 0),
            "ext_requests": (0, 0, 0, 0), "ext_replies": (0, 0, 0, 0),
            "delivered_events": (0, 0),
            "device_events": (X.KeyPress, X.MotionNotify),
            "errors": (0, 0),
            "client_started": False, "client_died": False,
        }],
    )
    record_dpy.record_enable_context(ctx, handler)


if __name__ == "__main__":
    main()
