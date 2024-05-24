#include <Arduino.h>

// const uint32_t g_ADigitalPinMap[] = {
//   // D0 - D7
//   11,
//   12,
//   13,
//   14,
//   15,
//   16,
//   17,
//   18,

//   // D8 - D13
//   19,
//   20,
//   22,
//   23,
//   24,
//   25,

//   // A0 - A7
//   3,
//   4,
//   28,
//   29,
//   30,
//   31,
//   5, // AIN3 (P0.05)
//   2, // AIN0 (P0.02) / AREF

//   // SDA, SCL
//   26,
//   27,

//   // RX, TX
//   8,
//   6
// };


#define MOTOR_PWM 21
#define SOL_ON_EN 24
#define SOL_DEG_EN 9
#define SOL_DEG_PWM 8
#define SOL_ON_PWM 20
#define MOTOR_UI 4
#define BUTTON 22

int pump_mode = 0; // 0 is swing, 1 is solo

int Build_up_swing[18] = {210, 240, 274, 282, 304, 324, 340, 352, 334, 240, 318, 392, 478, 568, 658, 722, 822, 898}; // first 9 are Stimulation, Last 9 are Expression
int PWM_swing[18] = {40, 46, 50, 56, 62, 68, 72, 78, 84, 36, 40, 46, 48, 54, 58, 62, 66, 70}; // first 9 are Stimulation, Last 9 are Expression

int Build_up_solo[18] = {196, 254, 254, 260, 314, 300, 379, 354, 340, 238, 332, 370, 456, 532, 592, 694, 800, 854}; // first 9 are Stimulation, Last 9 are Expression
int PWM_solo[18] = {26, 30, 32, 34, 38, 40, 42, 44, 46, 26, 28, 30, 32, 36, 38, 40, 42}; // first 9 are Stimulation, Last 9 are Expression

// int Build_up_[18] = {};
// int PWM_[18] = {};
// int Build_up_[18] = {};
// int PWM_[18] = {};
// int Build_up_[18] = {};

int *Build_up = Build_up_swing;
int *PWM = PWM_swing;

// put function declarations here:
int myFunction(int, int);
int myPWM(int, int, int);


void setup() {
  // put your setup code here, to run once:

  pinMode(MOTOR_PWM, OUTPUT);
  pinMode(MOTOR_UI, OUTPUT);
  pinMode(SOL_ON_EN, OUTPUT);
  // pinMode(SOL_DEG_EN, OUTPUT);
  // pinMode(SOL_DEG_PWM, OUTPUT);
  pinMode(SOL_ON_PWM, OUTPUT);
  pinMode(BUTTON, INPUT);
  // for (int i = 0; i < 22; i++) {
  //   pinMode(i, OUTPUT);
  // }

  
  // put your setup code here, to run once:
  // pinMode(MOTOR_PWM, OUTPUT);
}

void loop() {
  // put your main code here, to run repeatedly:
  // digitalWrite(SOL_DEG_EN, LOW);
  // digitalWrite(SOL_DEG_PWM, LOW);
  delay(1000);
  // digitalWrite(MOTOR_PWM, HIGH);
  // digitalWrite(MOTOR_PWM, HIGH);
  // digitalWrite(SOL_ON_EN, HIGH);
  // digitalWrite(SOL_ON_PWM, HIGH);

// PWM is 0-255, means 0 to 100% duty cycle, example 50 is 20% duty cycle (The formula is PWM/255 * 100%)
// Durata is in ms, example 1000 is 1 second
  int counter=0;
  delay(10);
  for(int i = 0; i <= 17; i += 1) {
      while(digitalRead(BUTTON) == LOW) {
        delay(10);
      }
      counter=0;
      while(digitalRead(BUTTON) == HIGH) {
        delay(100);
        counter+=1;
        if (counter > 10) {
          if(pump_mode == 0) {
            pump_mode = 1;
          } else {
            pump_mode = 0;
          }
          i=0;
          break;
        }
      }

      if (pump_mode == 0) {
        Build_up = Build_up_swing;
        PWM = PWM_swing;
      } else {
        Build_up = Build_up_solo;
        PWM = PWM_solo;
      }

      delay(500);
      // analogWrite(MOTOR_PWM, (1.5/4*255)); // We need to apply 1.5V for 35ms
      digitalWrite(SOL_ON_EN, LOW);
      digitalWrite(SOL_ON_PWM, LOW);
      // delay(35);
      for (int j = -40; j <= 40; j=j+10) {
      myPWM(35, (1.5/4*255), 20);
      myPWM(int((Build_up[i]-35)*(1+j/1000.0)), PWM[i]*255/100, 20);
      delay(50);
      digitalWrite(SOL_ON_EN, HIGH);
      digitalWrite(SOL_ON_PWM, HIGH);
      delay(500);
      digitalWrite(SOL_ON_EN, LOW);
      digitalWrite(SOL_ON_PWM, LOW);
      }
  }

  // while(1){
  //     delay(1000);
  //     digitalWrite(SOL_ON_EN, LOW);
  //     digitalWrite(SOL_ON_PWM, LOW);
  //     analogWrite(MOTOR_PWM, PWM);
  //     delay(build_up);
  //     analogWrite(MOTOR_PWM, 0);
  //     digitalWrite(SOL_ON_EN, HIGH);
  //     digitalWrite(SOL_ON_PWM, HIGH);
  //     delay(200);
  //     digitalWrite(SOL_ON_EN, LOW);
  //     digitalWrite(SOL_ON_PWM, LOW);
  //   }
  // digitalWrite(MOTOR_PWM, LOW);
  // digitalWrite(MOTOR_UI, LOW);
  
  // digitalWrite(SOL_ON_EN, LOW);
  // digitalWrite(SOL_ON_PWM, LOW);
  // delay(1000);
  // digitalWrite(SOL_ON_PWM, HIGH);
  // // analogWrite(SOL_PWM, 200);
  // delay(4000);
  // // analogWrite(SOL_PWM, 0);
  // digitalWrite(SOL_ON_PWM, LOW);
  // delay(1000);
  // digitalWrite(SOL_ON_EN, LOW);

  // for (int i = 0; i < 22; i++) {
  //   digitalWrite(i, HIGH);
  // }

  // delay(1000);
  // for (int i = 0; i < 22; i++) {
  // digitalWrite(i, LOW);
  // }

  while(1);


}

int myPWM(int durationMs, int PWM, int frequencyKhz) {
  int periodUs = 1E3/frequencyKhz;
  int onTime = periodUs * PWM / 255;
  int offTime = periodUs - onTime;
  int cycles = durationMs*1E3 / periodUs;
  for (int i = 0; i < cycles; i++) {
    digitalWrite(MOTOR_PWM, HIGH);
    nrf_delay_us(onTime);
    digitalWrite(MOTOR_PWM, LOW);
    nrf_delay_us(offTime);
  }
  return 1;
}