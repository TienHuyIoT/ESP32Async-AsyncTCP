#pragma once
#include "Arduino.h"
#include <functional>

typedef std::function<size_t(void *, const uint8_t*, size_t)> AcConsoleHandler;

class AsyncConsole : public Print
{
private:
    AcConsoleHandler _console_cb;
    void *_console_cb_arg;
public:
    AsyncConsole(/* args */);
    ~AsyncConsole();
    size_t write(uint8_t c) override { write(&c, 1); return 1; }
    size_t write(const uint8_t *buffer, size_t size) override;
    void onWrite(AcConsoleHandler cb, void *arg = nullptr);
};