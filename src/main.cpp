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


// put function declarations here:
int myFunction(int, int);


void setup() {
  // put your setup code here, to run once:

  pinMode(MOTOR_PWM, OUTPUT);
  pinMode(MOTOR_UI, OUTPUT);
  pinMode(SOL_ON_EN, OUTPUT);
  // pinMode(SOL_DEG_EN, OUTPUT);
  // pinMode(SOL_DEG_PWM, OUTPUT);
  pinMode(SOL_ON_PWM, OUTPUT);
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

  for(int PWM = 50; PWM < 250; PWM += 40) {
    for (int durata = 100; durata < 2000; durata += 200) {
      
      digitalWrite(SOL_ON_EN, LOW);
      digitalWrite(SOL_ON_PWM, LOW);
      analogWrite(MOTOR_PWM, PWM);
      delay(durata);
      analogWrite(MOTOR_PWM, 0);
      digitalWrite(SOL_ON_EN, HIGH);
      digitalWrite(SOL_ON_PWM, HIGH);
      delay(200);
      digitalWrite(SOL_ON_EN, LOW);
      digitalWrite(SOL_ON_PWM, LOW);
    }
  }




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

// put function definitions here:
int CloseSol(int timeMs) {
  digitalWrite(SOL_ON_EN, HIGH);
  digitalWrite(SOL_ON_PWM, HIGH);
  delay(timeMs);
  digitalWrite(SOL_ON_EN, HIGH);
  digitalWrite(SOL_ON_PWM, HIGH);
}