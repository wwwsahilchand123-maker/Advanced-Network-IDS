"""
Example WebSocket Client
For testing real-time event streaming
"""
import asyncio
import websockets
import json


async def listen_to_events():
    """
    Connect to IDS WebSocket and listen for events
    """
    # For authenticated connection, append token:
    # uri = "ws://localhost:8000/api/v1/ws/events?token=YOUR_JWT_TOKEN"
    uri = "ws://localhost:8000/api/v1/ws/events"
    
    async with websockets.connect(uri) as websocket:
        print(f"Connected to {uri}")
        
        # Send ping every 30 seconds
        async def ping_loop():
            while True:
                await asyncio.sleep(30)
                await websocket.send("ping")
                print("Sent ping")
        
        # Start ping task
        ping_task = asyncio.create_task(ping_loop())
        
        try:
            # Listen for messages
            async for message in websocket:
                data = json.loads(message)
                
                event_type = data.get("type")
                
                if event_type == "connection_established":
                    print("✓ Connection established")
                
                elif event_type == "new_alert":
                    alert = data["data"]
                    print(f"\n🚨 NEW ALERT:")
                    print(f"   Title: {alert['title']}")
                    print(f"   Severity: {alert['severity']}")
                    print(f"   Source: {alert.get('src_ip')}")
                    print(f"   Time: {alert['timestamp']}")
                
                elif event_type == "incident_update":
                    incident = data["data"]
                    print(f"\n🔴 INCIDENT UPDATE:")
                    print(f"   Title: {incident.get('title')}")
                    print(f"   Risk Score: {incident.get('risk_score')}")
                    print(f"   Severity: {incident.get('severity')}")
                
                elif event_type == "stats_update":
                    stats = data["data"]
                    capture = stats.get("capture", {})
                    print(f"\n📊 Stats: Packets={capture.get('packets_analyzed', 0)}, "
                          f"Flows={capture.get('active_flows', 0)}")
                
                elif event_type == "flow_update":
                    flows = data["data"]
                    print(f"\n🌐 Flow Update: {len(flows)} active flows")
                
                elif event_type == "pong":
                    print("Received pong")
        
        except KeyboardInterrupt:
            print("\nDisconnecting...")
        finally:
            ping_task.cancel()


if __name__ == "__main__":
    print("IDS WebSocket Client")
    print("Connecting to real-time event stream...")
    print("Press Ctrl+C to exit\n")
    
    asyncio.run(listen_to_events())
