import serial
import time
from icecream import ic

def write_read(x): 
    ser.write(bytes(x, 'utf-8')) 
    time.sleep(0.05) 
    data = ser.readline() 
    return data 

def read_string():
    while(1):
        if(ser.in_waiting>0):
            received_data = ""
            while True:
                char = ser.read().decode()
                if char == '\n':
                    break
                received_data += char.strip()
            return received_data
        

def read_int():
    while(1):
        if(ser.in_waiting>0):
            received_data = ser.read().decode().strip()
            if received_data.isdigit() :
                return received_data
            # else:
            #     ser.write(1)
        else:
            time.sleep(0.0001)

# Define the serial port and baud rate
serial_port = 'COM8'  # Replace with the appropriate port name
baud_rate = 115200  # Replace with the appropriate baud rate

# Create a serial object
ser = serial.Serial(serial_port, baud_rate)
if ser.is_open:
    ser.close()
# # Open the serial port
ser.open()

# Check if the serial port is open
if ser.is_open:
    print(f"Serial port {serial_port} is open.")
    received_data = ""
    ser.write(bytes("9", 'utf-8'))
    while( True):
        
        if(ser.in_waiting>0):
            received_data = read_int()
            # print(f"Received data: {received_data}")
        else:
            ser.write(bytes("9", 'utf-8'))
        time.sleep(0.1)
        if received_data == "9":
            received_data = read_int()
            if received_data == "1":
                received_data = read_int()
                if received_data == "3":
                    ser.write(bytes("1", 'utf-8'))
                    ser.flush()
                    break
    print("Connection established")
    
else:
    print(f"Failed to open serial port {serial_port}.")
time.sleep(0.02)

if(ser.in_waiting>0):
    received_data = read_int()

duty = input("Enter the duty cycle: ")

if int(duty)>=int("100"):
    print("Invalid input, too many pulses,limited to 95")
    duty="95"
if int(duty)< int("10"):
    duty = "0"+duty
dutyCycle=0

time.sleep(0.02)
ser.write(bytes(duty[0], 'utf-8'))
dutyCycle = int(read_int())*10
time.sleep(0.02)

ser.write(bytes(duty[1], 'utf-8'))
time.sleep(0.02)

dutyCycle += int(read_int())

time.sleep(0.02)


pulses= str(input("Enter the number of pulses: "))

if int(pulses)>=int("100"):
    print("Invalid input, too many pulses,limited to 99")
    pulses="99"
if int(pulses)<int("10"):
    pulses = "0"+pulses
N_pulses=0

ser.write(bytes(pulses[0], 'utf-8'))
N_pulses = int(read_int())*10
time.sleep(0.02)

ser.write(bytes(pulses[1], 'utf-8'))
time.sleep(0.02)

N_pulses += int(read_int())
time.sleep(0.02)


        

print(f"Duty is: {dutyCycle}")
print(f"Pulses are: {N_pulses}")
