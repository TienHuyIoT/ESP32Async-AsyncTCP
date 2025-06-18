#include "AsyncConsole.h"

static size_t _console_write(void *arg, const uint8_t *buffer, size_t size) {
    return Serial.write(buffer, size);
}

AsyncConsole::AsyncConsole() 
    : _console_cb(_console_write), _console_cb_arg(nullptr) {}

AsyncConsole::~AsyncConsole() {}

void AsyncConsole::onWrite(AcConsoleHandler cb, void *arg) {
    _console_cb = cb;
    _console_cb_arg = arg;
}

size_t AsyncConsole::write(const uint8_t *buffer, size_t size) {
    if (_console_cb) {
        _console_cb(_console_cb_arg, buffer, size);
        return size;
    }
    return 0;
}
