#include <Arduino.h>


const int outputPin = PA0;       // Define the output pin
const int LED = PA5;       // Define the output pin
const int frequency = 20E3;    // Period of the pulse in microseconds (1 second)
int dutyCycle = 20;      // Duty cycle in percentage (50% duty cycle)
int numPulses = 10;      // Number of pulses to generate

void SettingPWM(void);

void setup() {
  int period = 1E6 / frequency; // Calculate the period of the pulse in microseconds
  pinMode(outputPin, OUTPUT);  // Set the output pin as OUTPUT
  pinMode(LED, OUTPUT);  // Set the output pin as OUTPUT
  Serial.begin(9600);          // Initialize the serial port
}

void loop() {
  int period = 1E6 / frequency; // Calculate the period of the pulse in microseconds
  SettingPWM();
  for (int i = 0; i < numPulses; i++) {
    // Calculate the ON time and OFF time based on duty cycle and period
    int onTime = (period * dutyCycle) / 100;
    int offTime = period - onTime;

    // Output the pulse
    digitalWrite(outputPin, HIGH); // Turn the output pin ON
    delayMicroseconds(onTime);      // Wait for the ON time
    digitalWrite(outputPin, LOW);  // Turn the output pin OFF
    delayMicroseconds(offTime);     // Wait for the OFF time
  }
  
  // Stop generating pulses after numPulses
  Serial.print("Done");
  while (true) {
    delay(500); // Wait for 1 second
    digitalWrite(LED, HIGH); // Turn the output pin ON
    delay(500); // Wait for 1 second
    digitalWrite(LED, LOW); // Turn the output pin OFF

  }  // Empty loop to halt execution
  
}

void SettingPWM(void)   {
  int period = 1E6 / frequency; // Calculate the period of the pulse in microseconds
  Serial.print("Duty cycle: ");
  Serial.flush();
  while (!Serial.available()) {
    dutyCycle = Serial.parseInt();
  }
  Serial.print(dutyCycle);
  Serial.print("%");
  Serial.print("\n");
  Serial.print("Period: ");
  Serial.print(period);
  Serial.print(" microseconds");
  Serial.print("\n");
  Serial.print("Number of pulses: ");
  Serial.parseInt();
  delay(100);
  while (!Serial.available()) {
    numPulses = Serial.parseInt();
  }
  Serial.print(numPulses);
  Serial.print(" pulses");
  Serial.print("\n");
}