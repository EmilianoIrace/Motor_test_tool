#include <Arduino.h>


const int outputPin = PA0;       // Define the output pin
const int LED = PA5;       // Define the output pin
const int Solenoid = PA8;
const int frequency = 20E3;    // Period of the pulse in microseconds (1 second)
int dutyCycle = 20;      // Duty cycle in percentage (50% duty cycle)
int pulses = 10;      // Number of pulses to generate
int x=0;
char communication_p[]="Connection_pending ";
char communication_e[]="Connection_established";
char comm_value = '0';
int dutyCycle_1 = 0;
int dutyCycle_2 = 0;
int pulses_1 = 0;
int pulses_2 = 0;
void SettingPWM(void);

void setup() {
  int period = 1E6 / frequency; // Calculate the period of the pulse in microseconds
  pinMode(outputPin, OUTPUT);  // Set the output pin as OUTPUT
  pinMode(Solenoid, OUTPUT);  // Set the output pin as OUTPUT
  pinMode(LED, OUTPUT);  // Set the output pin as OUTPUT
  Serial.begin(115200);          // Initialize the serial port
}

void loop() {
  int period = 1E6 / frequency; // Calculate the period of the pulse in microseconds
  SettingPWM();
  digitalWrite(Solenoid, LOW); // Turn the output pin ON
  delay(10);
  for (int i = 0; i < pulses; i++) {
    // Calculate the ON time and OFF time based on duty cycle and period
    int onTime = (period * dutyCycle) / 100;
    int offTime = period - onTime;

    // Output the pulse
    digitalWrite(outputPin, HIGH); // Turn the output pin ON
    delayMicroseconds(onTime);      // Wait for the ON time
    digitalWrite(outputPin, LOW);  // Turn the output pin OFF
    delayMicroseconds(offTime);     // Wait for the OFF time
  }
  digitalWrite(Solenoid, HIGH); // Turn the output pin ON
  delay(800);
  digitalWrite(Solenoid, LOW); // Turn the output pin ON
  delay(800);
  
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
  // Serial.setTimeout(100);
  int period = 1E6 / frequency; // Calculate the period of the pulse in microseconds
  x=0;
  while (comm_value != '9') {
    if(Serial.available()>0){
      comm_value=Serial.read();
    }
  }

  while(comm_value!='1'){

    Serial.write('9');
    Serial.write('1');
    Serial.write('3');
    while(!Serial.available());
    comm_value=Serial.read();
    delay(10);
  }
  dutyCycle=0;
  delay(40);
  while(true){
    while(!Serial.available());
    dutyCycle_1=Serial.read();
    delay(10);
    while(Serial.available()){
      Serial.read();
    }
    Serial.write(dutyCycle_1);
    delay(10);

    while(!Serial.available());
    dutyCycle_2=Serial.read();
    delay(10);

    Serial.write(dutyCycle_2);
    delay(10);
    dutyCycle = (dutyCycle_1-'0')*10 + dutyCycle_2-'0';
    comm_value=Serial.read();
    if (comm_value=='5'){
      comm_value=Serial.read();
      if(comm_value=='2'){
        comm_value=Serial.read();
        if (comm_value=='3')
          break;
    }
  }
  while (true) {
  pulses=0;
  while(!Serial.available());
  pulses_1=Serial.read();
  delay(10);
  while(Serial.available()){
    Serial.read();
  }
  Serial.write(pulses_1);
  delay(10);

  while(!Serial.available());
  pulses_2=Serial.read();
  delay(10);

  Serial.write(pulses_2);
  delay(10);
  pulses = (pulses_1-'0')*10 + pulses_2-'0';

  comm_value=Serial.read();
    if (comm_value=='5'){
      comm_value=Serial.read();
      if(comm_value=='2'){
        comm_value=Serial.read();
        if (comm_value=='3')
          break;
    }
    }
  }
  }
  
  // Serial.print(dutyCycle);
  // Serial.print("%");
  // Serial.print("\n");
  // Serial.print("Period: ");
  // Serial.print(period);
  // Serial.print(" microseconds");
  // Serial.print("\n");
  // Serial.print("Number of pulses: ");
  // Serial.print("\n");
  // Serial.parseInt();
  // delay(10);
  // while (!Serial.available()) {
  //   numPulses = Serial.parseInt();
  // }
  // Serial.print(numPulses);
  // Serial.print(" pulses");
  // Serial.print("\n");
}