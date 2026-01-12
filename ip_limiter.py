import time
from fastapi import HTTPException

class IPLimiter:
    max_devices: int
    window_seconds: int
    _devices: dict[str, dict[str, list]]
    
    def __init__(self, max_devices: int, window_seconds: int) -> None:
        self.max_devices = max_devices
        self.window_seconds = window_seconds
        self._devices = dict()
    
    def limit(self, ip, device) -> None:
        ip_data = self._devices.get(ip, {"time": 0, "devices": []})
        
        set_time = ip_data["time"]
        current_time = time.time()
        if (set_time == 0) or (current_time - set_time >= self.window_seconds):
            ip_data["devices"].clear()
            ip_data["time"] = current_time
            
        devices = ip_data["devices"]
        if device not in devices and len(ip_data["devices"]) >= self.max_devices:
            raise HTTPException(429, "Maximum 2 devices")
        elif device not in devices:
            ip_data["devices"].append(device)
        
        self._devices[ip] = ip_data
        