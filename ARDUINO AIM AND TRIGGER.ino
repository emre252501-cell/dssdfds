//-----------------------------------------------------------------------------------//
#include <hidcomposite.h>
#include <usbhub.h>
#ifdef dobogusinclude
#include <spi4teensy3.h>
#endif
#include <SPI.h>
#include <Keyboard.h>
#include <Mouse.h>
#include <avr/pgmspace.h>
#include <Usb.h>
#include <hidboot.h>
byte bf[3];
//----------------------------------------//
class HIDSelector : public HIDComposite
{
public:
    HIDSelector(USB *p) : HIDComposite(p) {};

protected:
    void ParseHIDData(USBHID *hid, uint8_t ep, bool is_rpt_id, uint8_t len, uint8_t *buf); // Called by the HIDComposite library
    bool SelectInterface(uint8_t iface, uint8_t proto); 
};

bool HIDSelector::SelectInterface(uint8_t iface, uint8_t proto)
{
  if (proto != 0)
    return true;

  return false;
}

void HIDSelector::ParseHIDData(USBHID *hid, uint8_t ep, bool is_rpt_id, uint8_t len, uint8_t *buf) {
#if 1
  if (len && buf)  {
    Notify(PSTR("\r\n"), 0x80);
    for (uint8_t i = 0; i < len; i++) {
      D_PrintHex<uint8_t > (buf[i], 0x80);
      Notify(PSTR(" "), 0x80);
    }
  }
#endif
}
//----------------------------------------//
USB     Usb;
HIDSelector    HidMouse(&Usb);
//----------------------------------------//
struct {
    uint8_t buttons;
    int8_t x;
    int8_t y;
    int8_t wheel;
} mouseReport;
//----------------------------------------//
const byte buffSize = 32;
char inputSeveral[buffSize];

byte maxChars;

int inputInt = 0;
float inputFloat = 0.0;
char inputCsvString[12];
int x;
int y;
int shoot;
//-----------------------------------------------------------------------------------//
void MoveMouseToXY(long x, long y) {
  long max = max(abs(x), abs(y));
  int count = (int) (max / 127);
  signed char stepX = x / (count + 1);
  signed char stepY = y / (count + 1);
  for (int i = 0; i < count; i++) {
    Mouse.begin();
    Mouse.move(stepX, stepY);
    Mouse.end();
  }
  signed char resX = x - (stepX * count);
  signed char resY = y - (stepY * count);
  if (resX != 0 || resY != 0) {
    Mouse.begin();
    Mouse.move(resX, resY);
    Mouse.end();
  }
}
//-----------------------------------------------------------------------------------//
void showResults() {
  if (x != 0 || y != 0) {
    // Aimbot
    MoveMouseToXY(x, y);
  }

}
//-----------------------------------------------------------------------------------//
void readCSV() {
  if (Serial.available() > 0) {
    char cmd = Serial.read();

    // Mouse movement command
    if (cmd == 'M' && Serial.available() >= 2) { 
      Serial.readBytes(bf, 2);
      Mouse.move(bf[0], bf[1], 0);
    }
    // New: Left click command
    else if (cmd == 'K') {
      Mouse.click(MOUSE_LEFT);
    }
  }
}
//-----------------------------------------------------------------------------------//
class MouseRptParser : public MouseReportParser {
protected:
    virtual void OnMouseMove        (MOUSEINFO* mi);
    virtual void OnLeftButtonUp     (MOUSEINFO* mi);
    virtual void OnLeftButtonDown   (MOUSEINFO* mi);
    virtual void OnRightButtonUp    (MOUSEINFO* mi);
    virtual void OnRightButtonDown  (MOUSEINFO* mi);
    virtual void OnMiddleButtonUp   (MOUSEINFO* mi);
    virtual void OnMiddleButtonDown (MOUSEINFO* mi);
    virtual void OnX1ButtonUp       (MOUSEINFO *mi);
    virtual void OnX1ButtonDown     (MOUSEINFO *mi);
    virtual void OnX2ButtonUp       (MOUSEINFO *mi);
    virtual void OnX2ButtonDown     (MOUSEINFO *mi);
    virtual void OnWheelMove        (MOUSEINFO *mi);
};
void MouseRptParser::OnMouseMove(MOUSEINFO* mi)        {
  MoveMouseToXY(mi->dX, mi->dY);
};
void MouseRptParser::OnLeftButtonUp(MOUSEINFO* mi)     {
  Mouse.begin();
  Mouse.release(MOUSE_LEFT);
  Mouse.end();
};
void MouseRptParser::OnLeftButtonDown(MOUSEINFO* mi)   {
  Mouse.begin();
  Mouse.press(MOUSE_LEFT);
  Mouse.end();
};
void MouseRptParser::OnRightButtonUp(MOUSEINFO* mi)    {
  Mouse.begin();
  Mouse.release(MOUSE_RIGHT);
  Mouse.end();
};
void MouseRptParser::OnRightButtonDown(MOUSEINFO* mi)  {
  Mouse.begin();
  Mouse.press(MOUSE_RIGHT);
  Mouse.end();
};
void MouseRptParser::OnMiddleButtonUp(MOUSEINFO* mi)   {
  Mouse.begin();
  Mouse.release(MOUSE_MIDDLE);
  Mouse.end();
};
void MouseRptParser::OnMiddleButtonDown(MOUSEINFO* mi) {
  Mouse.begin();
  Mouse.press(MOUSE_MIDDLE);
  Mouse.end();
};
void MouseRptParser::OnX1ButtonUp(MOUSEINFO *mi)       {
  Mouse.begin();
  Mouse.release(MOUSE_BACK);
  Mouse.end();
};
void MouseRptParser::OnX1ButtonDown(MOUSEINFO *mi)     {
  Mouse.begin();
  Mouse.press(MOUSE_BACK);
  Mouse.end();
};
void MouseRptParser::OnX2ButtonUp(MOUSEINFO *mi)       {
  Mouse.begin();
  Mouse.release(MOUSE_FORWARD);
  Mouse.end();
};
void MouseRptParser::OnX2ButtonDown(MOUSEINFO *mi)     {
  Mouse.begin();
  Mouse.press(MOUSE_FORWARD);
  Mouse.end();
};
void MouseRptParser::OnWheelMove(MOUSEINFO *mi)        {
  Mouse.begin();
  Mouse.move(0, 0, mi->dZ);
  Mouse.end();
};
MouseRptParser Prs;

//-----------------------------------------------------------------------------------//

void setup() {
    Mouse.begin();
    Serial.begin(115200);
    Serial.setTimeout(1);
                      
    // Init USB/Mouse
    Usb.Init();
    HidMouse.SetReportParser(0, &Prs);
}

//-----------------------------------------------------------------------------------//
void loop() {
    Usb.Task();
    readCSV();
    showResults();
}
