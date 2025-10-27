# dump.py
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        payload = message.get('payload', {})
        if payload.get('type') == 'dump':
            filename = 'executevm.dump'
            with open(filename, 'wb') as f:
                f.write(data)
            print(f"[+] Saved {len(data)} bytes to {filename}")
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(['com.vpn.free.hotspot.secure.vpnify'])
session = device.attach(pid)

with open('frida-so.js', 'r') as f:
    script_code = f.read()

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
device.resume(pid)

print("[*] Running... Press Ctrl+C to exit")
sys.stdin.read()
