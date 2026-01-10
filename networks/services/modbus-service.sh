#!/bin/bash
# Modbus TCP Service Script for CORE Network Emulator
# Usage: modbus-service.sh [port] [device_type]
# Simulates a Modbus TCP device for ICS penetration testing

PORT=${1:-502}
DEVICE_TYPE=${2:-plc}

DATADIR="/var/modbus"
mkdir -p "$DATADIR"

# Create device info based on type
case "$DEVICE_TYPE" in
    plc)
        DEVICE_NAME="Siemens S7-1200"
        VENDOR="Siemens"
        PRODUCT="S7-1200 CPU 1214C"
        FIRMWARE="V4.4.0"
        ;;
    rtu)
        DEVICE_NAME="SEL-3530 RTAC"
        VENDOR="Schweitzer Engineering"
        PRODUCT="Real-Time Automation Controller"
        FIRMWARE="R134-V0"
        ;;
    scada)
        DEVICE_NAME="Schneider ClearSCADA"
        VENDOR="Schneider Electric"
        PRODUCT="ClearSCADA Server"
        FIRMWARE="2021 R2"
        ;;
    *)
        DEVICE_NAME="Generic Modbus Device"
        VENDOR="Unknown"
        PRODUCT="Modbus TCP Slave"
        FIRMWARE="1.0"
        ;;
esac

# Create device info file
cat > "$DATADIR/device_info.txt" << EOF
Device: $DEVICE_NAME
Vendor: $VENDOR
Product: $PRODUCT
Firmware: $FIRMWARE
Modbus Address: 1
EOF

# Create simulated register values
cat > "$DATADIR/registers.txt" << 'EOF'
# Holding Registers (40001-40100)
40001: 1234  # Process Value 1
40002: 5678  # Process Value 2
40003: 100   # Setpoint 1
40004: 200   # Setpoint 2
40005: 1     # Operating Mode
40006: 0     # Alarm Status
40007: 72    # Temperature
40008: 147   # Pressure (x10)
40009: 2503  # Flow Rate
40010: 85    # Level %

# Coils (00001-00100)
00001: 1  # Pump 1 Running
00002: 0  # Pump 2 Running
00003: 1  # Valve 1 Open
00004: 0  # Valve 2 Open
00005: 0  # Emergency Stop
00006: 1  # System Ready
00007: 0  # Alarm Active
00008: 1  # Remote Mode

# Input Registers (30001-30100)
30001: 725  # Sensor 1 Raw
30002: 483  # Sensor 2 Raw
30003: 982  # Sensor 3 Raw
30004: 156  # Sensor 4 Raw
EOF

echo "[+] Starting Modbus TCP service on port $PORT"
echo "[+] Device: $DEVICE_NAME"

# Check if pymodbus is available
if python3 -c "import pymodbus" 2>/dev/null; then
    # Use pymodbus for full Modbus implementation
    python3 << 'PYEOF' &
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
import threading

# Initialize data blocks
coils = ModbusSequentialDataBlock(0, [1,0,1,0,0,1,0,1] + [0]*92)
discrete_inputs = ModbusSequentialDataBlock(0, [1,1,0,1,0,0,1,0] + [0]*92)
holding_registers = ModbusSequentialDataBlock(0, [1234,5678,100,200,1,0,72,147,2503,85] + [0]*90)
input_registers = ModbusSequentialDataBlock(0, [725,483,982,156] + [0]*96)

store = ModbusSlaveContext(
    di=discrete_inputs,
    co=coils,
    hr=holding_registers,
    ir=input_registers
)
context = ModbusServerContext(slaves=store, single=True)

print("[+] Starting pymodbus server...")
StartTcpServer(context=context, address=("0.0.0.0", 502))
PYEOF
    echo "[+] pymodbus Modbus server started"
else
    # Simple Modbus TCP responder
    echo "[*] pymodbus not found, using simple Modbus responder"
    (
        while true; do
            # Read Modbus TCP request and respond
            # This provides basic function code responses
            {
                # Read 12-byte Modbus TCP header minimum
                read -r -n 12 request
                if [ -n "$request" ]; then
                    # Simple response for common function codes
                    # FC 1 (Read Coils): Return 8 coils
                    # FC 3 (Read Holding Registers): Return 10 registers
                    # FC 4 (Read Input Registers): Return 4 registers

                    # Generic response with holding register data
                    printf '\x00\x01\x00\x00\x00\x17\x01\x03\x14\x04\xd2\x16\x2e\x00\x64\x00\xc8\x00\x01\x00\x00\x00\x48\x00\x93\x09\xc7\x00\x55'
                fi
            } | nc -l -p "$PORT" -q 1
        done
    ) &
    echo "[+] Simple Modbus responder started"
fi

# Also start DNP3 if this is an RTU
if [ "$DEVICE_TYPE" = "rtu" ]; then
    echo "[+] Starting DNP3 service on port 20000"
    (
        while true; do
            # DNP3 start bytes and simple response
            printf '\x05\x64\x05\xc0\x01\x00\x00\x00\x04\xe9\x21' | nc -l -p 20000 -q 1
        done
    ) &
fi

# Start S7comm if this is a Siemens PLC
if [ "$DEVICE_TYPE" = "plc" ]; then
    echo "[+] Starting S7comm service on port 102"
    (
        while true; do
            # S7comm COTP connection confirm
            printf '\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x09' | nc -l -p 102 -q 1
        done
    ) &
fi

echo "[+] Modbus service configuration complete"
echo "[+] Function codes supported:"
echo "    - FC 01: Read Coils"
echo "    - FC 02: Read Discrete Inputs"
echo "    - FC 03: Read Holding Registers"
echo "    - FC 04: Read Input Registers"
echo "    - FC 05: Write Single Coil"
echo "    - FC 06: Write Single Register"
