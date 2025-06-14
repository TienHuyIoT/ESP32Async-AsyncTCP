// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright 2016-2025 Hristo Gochkov, Mathieu Carbou, Emil Muratov

#include "AsyncTCP.h"
#include "AsyncTCPSimpleIntrusiveList.h"

#ifndef LIBRETINY
#include <esp_log.h>

#ifdef ARDUINO
#include "Arduino.h"
#include <esp32-hal.h>
#include <esp32-hal-log.h>
#if (ESP_IDF_VERSION_MAJOR >= 5)
#include <NetworkInterface.h>
#endif
#else
#include "esp_timer.h"
#define log_e(...) ESP_LOGE(__FILE__, __VA_ARGS__)
#define log_w(...) ESP_LOGW(__FILE__, __VA_ARGS__)
#define log_i(...) ESP_LOGI(__FILE__, __VA_ARGS__)
#define log_d(...) ESP_LOGD(__FILE__, __VA_ARGS__)
#define log_v(...) ESP_LOGV(__FILE__, __VA_ARGS__)
static unsigned long millis() {
  return (unsigned long)(esp_timer_get_time() / 1000ULL);
}
#endif
#endif

#ifdef LIBRETINY
#include <Arduino.h>
// LibreTiny does not support IDF - disable code that expects it to be available
#define ESP_IDF_VERSION_MAJOR (0)
// xTaskCreatePinnedToCore is not available, force single-core operation
#define CONFIG_FREERTOS_UNICORE 1
// ESP watchdog is not available
#undef CONFIG_ASYNC_TCP_USE_WDT
#define CONFIG_ASYNC_TCP_USE_WDT 0
#endif

#include <assert.h>

extern "C" {
#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/inet.h"
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
}

#if CONFIG_ASYNC_TCP_USE_WDT
#include "esp_task_wdt.h"
#endif

#define ASYNC_TCP_CONSOLE_I(f_, ...)  //Serial.printf_P(PSTR("I [AsyncTCP] %s(), line %u: " f_ "\r\n"),  __func__, __LINE__, ##__VA_ARGS__)
#define ASYNC_TCP_CONSOLE_E(f_, ...)  Serial.printf_P(PSTR("E [AsyncTCP] %s(), line %u: " f_ "\r\n"),  __func__, __LINE__, ##__VA_ARGS__)

// Required for:
// https://github.com/espressif/arduino-esp32/blob/3.0.3/libraries/Network/src/NetworkInterface.cpp#L37-L47

#if CONFIG_ASYNC_TCP_USE_WDT
#include "esp_task_wdt.h"
#if (ESP_IDF_VERSION_MAJOR >= 4) // IDF 4+
#define ASYNC_TCP_MAX_TASK_SLEEP (pdMS_TO_TICKS(1000 * CONFIG_ESP_TASK_WDT_TIMEOUT_S) / 4)
#else
#define ASYNC_TCP_MAX_TASK_SLEEP (pdMS_TO_TICKS(1000 * CONFIG_TASK_WDT_TIMEOUT_S) / 4)
#endif
#else
#define ASYNC_TCP_MAX_TASK_SLEEP portMAX_DELAY
#endif

// https://github.com/espressif/arduino-esp32/issues/10526
namespace {
#ifdef CONFIG_LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
  bool do_lock;
  inline tcp_core_guard() : do_lock(!sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
    if (do_lock) {
      LOCK_TCPIP_CORE();
    }
  }
  inline ~tcp_core_guard() {
    if (do_lock) {
      UNLOCK_TCPIP_CORE();
    }
  }
  tcp_core_guard(const tcp_core_guard &) = delete;
  tcp_core_guard(tcp_core_guard &&) = delete;
  tcp_core_guard &operator=(const tcp_core_guard &) = delete;
  tcp_core_guard &operator=(tcp_core_guard &&) = delete;
} __attribute__((unused));
#else   // CONFIG_LWIP_TCPIP_CORE_LOCKING
struct tcp_core_guard {
} __attribute__((unused));
#endif  // CONFIG_LWIP_TCPIP_CORE_LOCKING
}  // anonymous namespace

#define INVALID_CLIENT_SLOT (s8_t)(-1)

/*
  TCP poll interval is specified in terms of the TCP coarse timer interval, which is called twice a second
  https://github.com/espressif/esp-lwip/blob/2acf959a2bb559313cd2bf9306c24612ba3d0e19/src/core/tcp.c#L1895
*/
#define CONFIG_ASYNC_TCP_POLL_TIMER 2 // Called every 2 * 500ms

typedef void (*tcp_close_callback)(void *arg);
typedef void (*tcp_abort_callback)(void *arg);
/*
 * TCP/IP API Calls private prototype
 * */
static err_t _tcp_output(struct tcpip_api_call_data *api_call_msg);
static esp_err_t _tcp_write(tcp_pcb *pcb, s8_t client_slot, const char *data, size_t size, uint8_t apiflags);
// static esp_err_t _tcp_recved(tcp_pcb *pcb, s8_t client_slot, size_t len);
static esp_err_t _tcp_close(tcp_pcb *pcb, s8_t client_slot, tcp_close_callback cb, void *arg);
static esp_err_t _tcp_abort(tcp_pcb *pcb, s8_t client_slot, tcp_abort_callback cb, void *arg);
static esp_err_t _tcp_connect(tcp_pcb *pcb, s8_t client_slot, ip_addr_t *addr, uint16_t port, tcp_connected_fn cb, void *arg);
static esp_err_t _dns_gethostbyname(const char *hostname, ip_addr_t *addr, dns_found_callback found, void *arg);
static tcp_pcb *_tcp_new_ip_type(u8_t type);

/*
 * TCP/IP Event Task
 * */

typedef enum {
  LWIP_TCP_NONE,
  LWIP_TCP_SENT,
  LWIP_TCP_RECV,
  LWIP_TCP_FIN,
  LWIP_TCP_DISCONNECT,
  LWIP_TCP_ERROR,
  LWIP_TCP_POLL,
  LWIP_TCP_ACCEPT,
  LWIP_TCP_CONNECTED,
  LWIP_TCP_DNS,
  LWIP_TCP_CALLBACK
} lwip_tcp_event_t;

struct lwip_tcp_event_packet_t {
  lwip_tcp_event_packet_t *next;
  lwip_tcp_event_t event;
  AsyncClient *client;
  union {
    struct {
      void *arg;
      asynctcp_callback_fn fn;
    } callback;
    struct {
      tcp_pcb *pcb;
      err_t err;
    } connected;
    struct {
      err_t err;
    } error;
    struct {
      tcp_pcb *pcb;
      uint16_t len;
    } sent;
    struct {
      tcp_pcb *pcb;
      pbuf *pb;
      err_t err;
    } recv;
    struct {
      tcp_pcb *pcb;
      err_t err;
    } fin;
    struct {
      tcp_pcb *pcb;
    } poll;
    struct {
      AsyncServer *server;
    } accept;
    struct {
      const char *name;
      ip_addr_t addr;
    } dns;
    struct {
      err_t err;
    } disconnect;
  };

  inline lwip_tcp_event_packet_t(lwip_tcp_event_t _event, AsyncClient *_client) : next(nullptr), event(_event), client(_client){};
};

// Detail class for interacting with AsyncClient internals, but without exposing the API
class AsyncTCP_detail {
public:
  // Helper function is called in Async thread
  static void __attribute__((visibility("internal"))) handle_async_event(lwip_tcp_event_packet_t *event);

  // LwIP TCP event callbacks that (will) require privileged access
  static err_t __attribute__((visibility("internal"))) tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, err_t err);
  static err_t __attribute__((visibility("internal"))) tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len);
  static void __attribute__((visibility("internal"))) tcp_error(void *arg, err_t err);
  static err_t __attribute__((visibility("internal"))) tcp_poll(void *arg, struct tcp_pcb *pcb);
  static err_t __attribute__((visibility("internal"))) tcp_accept(void *arg, tcp_pcb *pcb, err_t err);
  static err_t __attribute__((visibility("internal"))) tcp_connected(void *arg, tcp_pcb *pcb, err_t err) ;
  static void __attribute__((visibility("internal"))) _tcp_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg);
};

// Guard class for the global queue
namespace {

static SemaphoreHandle_t _async_queue_mutex = nullptr;

class queue_mutex_guard {
  bool holds_mutex;

public:
  inline queue_mutex_guard() : holds_mutex(xSemaphoreTake(_async_queue_mutex, portMAX_DELAY)){};
  inline ~queue_mutex_guard() {
    if (holds_mutex) {
      xSemaphoreGive(_async_queue_mutex);
    }
  };
  inline explicit operator bool() const {
    return holds_mutex;
  };
};
}  // anonymous namespace

static AsyncClient *_clients[CONFIG_LWIP_MAX_ACTIVE_TCP];
/**
 * If all access to _clients[] happens inside the lwIP thread, then client_mutex is not strictly needed.
 * But in practice, adding a mutex:
 *  - Protects from subtle bugs if code changes later.
 *  - Makes the code robust and reusable in mixed-thread contexts.
 *  - Is low-overhead on ESP32 FreeRTOS.
*/
static SemaphoreHandle_t _client_slot_mutex;
#define _xClientSlotTake() xSemaphoreTake(_client_slot_mutex, portMAX_DELAY)
#define _xClientSlotGive() xSemaphoreGive(_client_slot_mutex)

/**
 * Helper: Management Clients slot inside LwIP thread
*/
static s8_t _client_slot_available() {
  s8_t slot = INVALID_CLIENT_SLOT;
  _xClientSlotTake();
  for (u8_t i = 0; i < CONFIG_LWIP_MAX_ACTIVE_TCP; ++i) {
    if (!_clients[i]) {
      slot = i;
      break;
    }
  }
  _xClientSlotGive();
  return slot;
}

static s8_t _register_client_slot(AsyncClient *client) {
  if (!client) {
    return INVALID_CLIENT_SLOT;
  }
  s8_t slot = INVALID_CLIENT_SLOT;
  _xClientSlotTake();
  for (u8_t i = 0; i < CONFIG_LWIP_MAX_ACTIVE_TCP; ++i) {
    if (!_clients[i]) {
      _clients[i] = client;
      slot = i;
      ASYNC_TCP_CONSOLE_I("Slot[%d] = %u", i, client);
      break;
    }
  }
  _xClientSlotGive();
  return slot;
}

static s8_t _unregister_client_slot(AsyncClient *client) {
  if (!client) {
    return INVALID_CLIENT_SLOT;
  }
  s8_t slot = INVALID_CLIENT_SLOT;
  _xClientSlotTake();
  for (u8_t i = 0; i < CONFIG_LWIP_MAX_ACTIVE_TCP; ++i) {
    if (_clients[i] == client) {
      _clients[i] = NULL;
      slot = i;
      ASYNC_TCP_CONSOLE_I("Slot[%d] = %u", i, client);
      break;
    }
  }
  _xClientSlotGive();
  return slot;
}

static bool _is_client_slot_valid(AsyncClient *client) {
  if (!client) {
    return false;
  }
  bool found = false;
  _xClientSlotTake();
  for (u8_t i = 0; i < CONFIG_LWIP_MAX_ACTIVE_TCP; ++i) {
    if (_clients[i] == client) {
      found = true;
      break;
    }
  }
  _xClientSlotGive();
  return found;
}

static bool _is_pcb_slot_valid(s8_t slot, tcp_pcb *pcb) {
  if (slot != INVALID_CLIENT_SLOT && slot < CONFIG_LWIP_MAX_ACTIVE_TCP) {
    AsyncClient *c = _clients[slot];
    return (c && c->_pcb == pcb);
  } else {
    ASYNC_TCP_CONSOLE_I("Error due to Slot = %d", slot);
  }
  return false;
}

/**
 * Event management
*/
static SimpleIntrusiveList<lwip_tcp_event_packet_t> _async_queue;
static TaskHandle_t _async_service_task_handle = NULL;

static void _free_event(lwip_tcp_event_packet_t *e) {
  if ((e->event == LWIP_TCP_RECV) && e->recv.pb) {
    pbuf *pb = e->recv.pb;
    ASYNC_TCP_CONSOLE_I("Free ev: client %u pb = %u ref = %u", e->client, pb, pb->ref);
    pbuf_free(pb);
  }
  delete e;
}

static inline void _send_async_event(lwip_tcp_event_packet_t *e) {
  assert(e != nullptr);
  _async_queue.push_back(e);
  xTaskNotifyGive(_async_service_task_handle);
}

static inline void _prepend_async_event(lwip_tcp_event_packet_t *e) {
  assert(e != nullptr);
  _async_queue.push_front(e);
  xTaskNotifyGive(_async_service_task_handle);
}

static inline lwip_tcp_event_packet_t *_get_async_event() {
  queue_mutex_guard guard;
  while (1) {
    lwip_tcp_event_packet_t *e = _async_queue.pop_front();

    if ((!e) || (e->event != LWIP_TCP_POLL)) {
      return e;
    }

    /*
      Let's try to coalesce two (or more) consecutive poll events into one
      this usually happens with poor implemented user-callbacks that are runs too long and makes poll events to stack in the queue
      if consecutive user callback for a same connection runs longer that poll time then it will fill the queue with events until it deadlocks.
      This is a workaround to mitigate such poor designs and won't let other events/connections to starve the task time.
      It won't be effective if user would run multiple simultaneous long running callbacks due to message interleaving.
      todo: implement some kind of fair dequeuing or (better) simply punish user for a bad designed callbacks by resetting hog connections
    */
    for (lwip_tcp_event_packet_t *next_pkt = _async_queue.begin(); next_pkt && (next_pkt->client == e->client) && (next_pkt->event == LWIP_TCP_POLL);
         next_pkt = _async_queue.begin()) {
      // if the next event that will come is a poll event for the same connection, we can discard it and continue
      _free_event(_async_queue.pop_front());
      log_d("coalescing polls, network congestion or async callbacks might be too slow!");
    }

    /*
      now we have to decide if to proceed with poll callback handler or discard it?
      poor designed apps using asynctcp without proper dataflow control could flood the queue with interleaved pool/ack events.
      I.e. on each poll app would try to generate more data to send, which in turn results in additional ack event triggering chain effect
      for long connections. Or poll callback could take long time starving other connections. Anyway our goal is to keep the queue length
      grows under control (if possible) and poll events are the safest to discard.
      Let's discard poll events processing using linear-increasing probability curve when queue size grows over 3/4
      Poll events are periodic and connection could get another chance next time
    */
    if (_async_queue.size() > (rand() % CONFIG_ASYNC_TCP_QUEUE_SIZE / 4 + CONFIG_ASYNC_TCP_QUEUE_SIZE * 3 / 4)) {
      _free_event(e);
      log_d("discarding poll due to queue congestion");
      continue;
    }

    return e;
  }
}

static void _remove_events_for_client(AsyncClient *client) {
  lwip_tcp_event_packet_t *removed_event_chain;
  {
    queue_mutex_guard guard;
    removed_event_chain = _async_queue.remove_if([client](lwip_tcp_event_packet_t &pkt) {
      return pkt.client == client;
    });
  }

  while (removed_event_chain) {
    auto t = removed_event_chain;
    removed_event_chain = t->next;
    _free_event(t);
  }
};

void AsyncTCP_detail::handle_async_event(lwip_tcp_event_packet_t *e) {
  if (e->client == NULL) {
    if (e->event == LWIP_TCP_CALLBACK) {
      e->callback.fn(e->callback.arg);
    }
    return;
  }

  if (e->event == LWIP_TCP_RECV) {
    // ets_printf("-R: 0x%08x\n", e->recv.pcb);
    e->client->_recv(e->recv.pcb, e->recv.pb, e->recv.err);
    e->recv.pb = nullptr;  // avoid _free_event() shall call pbuf_free() again due to _recv() called pbuf_free() inside.
  } else if (e->event == LWIP_TCP_FIN) {
    // ets_printf("-F: 0x%08x\n", e->fin.pcb);
    e->client->_fin(e->fin.pcb, e->fin.err);
  } else if (e->event == LWIP_TCP_DISCONNECT) {
    // ets_printf("-F: 0x%08x\n", e->fin.pcb);
    e->client->_disconnect(e->fin.err);
  } else if (e->event == LWIP_TCP_SENT) {
    // ets_printf("-S: 0x%08x\n", e->sent.pcb);
    e->client->_sent(e->sent.pcb, e->sent.len);
  } else if (e->event == LWIP_TCP_POLL) {
    // ets_printf("-P: 0x%08x\n", e->poll.pcb);
    e->client->_poll(e->poll.pcb);
  } else if (e->event == LWIP_TCP_ERROR) {
    // ets_printf("-E: 0x%08x %d\n", e->client, e->error.err);
    e->client->_error(e->error.err);
  } else if (e->event == LWIP_TCP_CONNECTED) {
    // ets_printf("C: 0x%08x 0x%08x %d\n", e->client, e->connected.pcb, e->connected.err);
    e->client->_connected(e->connected.pcb);
  } else if (e->event == LWIP_TCP_ACCEPT) {
    // ets_printf("A: 0x%08x 0x%08x\n", e->client, e->accept.client);
    e->accept.server->_accepted(e->client);
  } else if (e->event == LWIP_TCP_DNS) {
    // ets_printf("D: 0x%08x %s = %s\n", e->client, e->dns.name, ipaddr_ntoa(&e->dns.addr));
    e->client->_dns_found(&e->dns.addr);
  }
}

/**
 * AsyncTCP thread
*/
static void _async_service_task(void *pvParameters) {
#if CONFIG_ASYNC_TCP_USE_WDT
  if (esp_task_wdt_add(NULL) != ESP_OK) {
    log_w("Failed to add async task to WDT");
  }
#endif
  for (;;) {
    while (auto packet = _get_async_event()) {
      AsyncTCP_detail::handle_async_event(packet);
      _free_event(packet);
#if CONFIG_ASYNC_TCP_USE_WDT
      esp_task_wdt_reset();
#endif
    }
    // queue is empty
    // DEBUG_PRINTF("Async task waiting 0x%08",(intptr_t)_async_queue_head);
    ulTaskNotifyTake(pdTRUE, ASYNC_TCP_MAX_TASK_SLEEP);
    // DEBUG_PRINTF("Async task woke = %d 0x%08x",q, (intptr_t)_async_queue_head);
#if CONFIG_ASYNC_TCP_USE_WDT
    esp_task_wdt_reset();
#endif
  }
#if CONFIG_ASYNC_TCP_USE_WDT
  esp_task_wdt_delete(NULL);
#endif
  vTaskDelete(NULL);
  _async_service_task_handle = NULL;
}

/*
static void _stop_async_task(){
    if(_async_service_task_handle){
        vTaskDelete(_async_service_task_handle);
        _async_service_task_handle = NULL;
    }
}
*/

static bool customTaskCreateUniversal(
  TaskFunction_t pxTaskCode, const char *const pcName, const uint32_t usStackDepth, void *const pvParameters, UBaseType_t uxPriority,
  TaskHandle_t *const pxCreatedTask, const BaseType_t xCoreID
) {
#ifndef CONFIG_FREERTOS_UNICORE
  if (xCoreID >= 0 && xCoreID < 2) {
    return xTaskCreatePinnedToCore(pxTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pxCreatedTask, xCoreID);
  } else {
#endif
    return xTaskCreate(pxTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pxCreatedTask);
#ifndef CONFIG_FREERTOS_UNICORE
  }
#endif
}

static bool _start_async_task() {
  if (!_async_queue_mutex) {
    _async_queue_mutex = xSemaphoreCreateMutex();
    if (!_async_queue_mutex) {
      return false;
    }
  }

  if (!_client_slot_mutex) {
    _client_slot_mutex = xSemaphoreCreateMutex();
    if (!_client_slot_mutex) {
      return false;
    }
  }

  if (!_async_service_task_handle) {
    customTaskCreateUniversal(
      _async_service_task, "async_tcp", CONFIG_ASYNC_TCP_STACK_SIZE, NULL, CONFIG_ASYNC_TCP_PRIORITY, &_async_service_task_handle, CONFIG_ASYNC_TCP_RUNNING_CORE
    );
    if (!_async_service_task_handle) {
      return false;
    }
  }
  return true;
}

/*
 * LwIP Callbacks
 * */

// For safe: only run in LwIP callbacks or TPC/IP raw API tcpip_api_call and tcpip_callback
static void _bind_tcp_callbacks(tcp_pcb *pcb, AsyncClient *client) {
  tcp_arg(pcb, client);
  tcp_recv(pcb, &AsyncTCP_detail::tcp_recv);
  tcp_sent(pcb, &AsyncTCP_detail::tcp_sent);
  tcp_err(pcb, &AsyncTCP_detail::tcp_error);
  tcp_poll(pcb, &AsyncTCP_detail::tcp_poll, CONFIG_ASYNC_TCP_POLL_TIMER);
}

// For safe: only run in LwIP callbacks or TPC/IP raw API tcpip_api_call and tcpip_callback
static void _reset_tcp_callbacks(tcp_pcb *pcb, AsyncClient *client) {
  tcp_arg(pcb, NULL);
  tcp_sent(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
}

// TCP Server: listen pcb callback
err_t AsyncTCP_detail::tcp_accept(void *arg, tcp_pcb *c_pcb, err_t err) {
  AsyncServer *s = reinterpret_cast<AsyncServer *>(arg);
  AsyncClient *c = (ERR_OK == err && c_pcb && s) ? new (std::nothrow) AsyncClient(c_pcb, s) : nullptr;
  lwip_tcp_event_packet_t *e = (c) ? new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ACCEPT, c} : nullptr;
  s8_t slot = (e) ? _register_client_slot(c) : INVALID_CLIENT_SLOT;
  bool accepted = (slot != INVALID_CLIENT_SLOT && s->_listen_connect_cb) ? true : false;

  if (!accepted) {
    ASYNC_TCP_CONSOLE_E("Accept failed: %d", err);

    if (e) {
      delete e;
    }
    
    if (c) {
      delete c;
    }
    
    if (slot != INVALID_CLIENT_SLOT) {
      _unregister_client_slot(c);
    }

    // Check if c_pcb was allocated
    if (c_pcb) {
      tcp_abort(c_pcb);
      // https://github.com/espressif/esp-lwip/blob/master/src/core/tcp.c#L636
      return ERR_ABRT;  // correct after aborting
    }
    return ERR_MEM;  // Didn't abort anything, just report resource issue
  }
  
  queue_mutex_guard guard;
  c->_pcb = c_pcb;
  c->_slot = slot;  // now slot is valid
  e->client = c;
  e->accept.server = s;
  _bind_tcp_callbacks(c_pcb, c);
  _prepend_async_event(e);
  return ERR_OK;
}

/**
 * TCP Client: connection callback
 * Do not need to call tcp_abort(pcb).
 * Just only need to return error status and leave the _tcp_connect_api handle.
*/
err_t AsyncTCP_detail::tcp_connected(void *arg, tcp_pcb *pcb, err_t err) {
  AsyncClient *c = reinterpret_cast<AsyncClient *>(arg);
  lwip_tcp_event_packet_t *e = (ERR_OK == err && pcb && c) ? new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_CONNECTED, c} : nullptr;
  s8_t slot = (e) ? _register_client_slot(c) : INVALID_CLIENT_SLOT;
  if (INVALID_CLIENT_SLOT == slot) {
    ASYNC_TCP_CONSOLE_E("Connection failed");
    if (e) {
      delete e;
    }
    return ERR_MEM;
  }
  queue_mutex_guard guard;
  c->_pcb = pcb;
  c->_slot = slot; // now slot is valid 
  e->connected.pcb = pcb;
  _bind_tcp_callbacks(pcb, c);
  _prepend_async_event(e);
  return ERR_OK;
}

err_t AsyncTCP_detail::tcp_poll(void *arg, struct tcp_pcb *pcb) {
  // throttle polling events queueing when event queue is getting filled up, let it handle _onack's
  {
    queue_mutex_guard guard;
    if (_async_queue.size() > (rand() % CONFIG_ASYNC_TCP_QUEUE_SIZE / 4 + CONFIG_ASYNC_TCP_QUEUE_SIZE * 3 / 4)) {
      ASYNC_TCP_CONSOLE_E("throttling");
      return ERR_OK;
    }
  }

  AsyncClient *c = reinterpret_cast<AsyncClient *>(arg);
  bool slot = _is_client_slot_valid(c);
  lwip_tcp_event_packet_t *e = (slot) ? new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_POLL, c} : nullptr;
  if (!e) {
    ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
    if (slot) {
      c->_lwip_abort(pcb);
      c->_error(ERR_MEM);
    } else {
      tcp_abort(pcb);
    }
    return ERR_ABRT;  // Tell lwIP we're killing it immediately
  }
  e->poll.pcb = pcb;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

/**
 * _lwip_close --> _fin --> _disconnect() --> ~AsyncClient()
 * _lwip_abort --> _error --> _disconnect() --> ~AsyncClient()
*/
err_t AsyncTCP_detail::tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *pb, err_t err) {
  AsyncClient *c = reinterpret_cast<AsyncClient *>(arg);
  bool slot = _is_client_slot_valid(c);
  lwip_tcp_event_packet_t *e = (slot) ? new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_RECV, c} : nullptr;
  if (!e) {
    ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
    if (pb) {
      if (err == ERR_OK) tcp_recved(pcb, pb->tot_len);
      pbuf_free(pb);
    }
    if (slot) {
      c->_lwip_abort(pcb);
      c->_error(ERR_MEM);
    } else {
      tcp_abort(pcb);
    }
    return ERR_ABRT;  // Tell lwIP we're killing it immediately
  }

  e->recv.pcb = pcb;
  e->recv.err = err;
  e->recv.pb = pb;

  if (pb) {
    if (err != ERR_OK) {
      ASYNC_TCP_CONSOLE_E("err %s", c->errorToString(err));
      delete e;
      pbuf_free(pb);
      c->_lwip_abort(pcb);
      c->_error(err);
      return ERR_ABRT;  // Tell lwIP we're killing it immediately
    }

    // ASYNC_TCP_CONSOLE_I("pb = %u tot_len = %u len = %u ref = %u", pb, pb->tot_len, pb->len, pb->ref);
    tcp_recved(pcb, pb->tot_len);
    // pbuf_free(pb);  // Async task shall handle pbuf_free(pb)
  } else {
    e->event = LWIP_TCP_FIN;
    err = c->_lwip_close(pcb);
  }

  queue_mutex_guard guard;
  _send_async_event(e);
  if (err != ERR_OK) {
    ASYNC_TCP_CONSOLE_E("Return %s", c->errorToString(err));
  }
  return err;
}

err_t AsyncTCP_detail::tcp_sent(void *arg, struct tcp_pcb *pcb, uint16_t len) {
  AsyncClient *c = reinterpret_cast<AsyncClient *>(arg);
  bool slot = _is_client_slot_valid(c);
  lwip_tcp_event_packet_t *e = (c) ? new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_SENT, c} : nullptr;
  if (!e) {
    ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
    if (slot) {
      c->_lwip_abort(pcb);
      c->_error(ERR_MEM);
    } else {
      tcp_abort(pcb);
    }
    return ERR_ABRT;  // Tell lwIP we're killing it immediately
  }
  e->sent.pcb = pcb;
  e->sent.len = len;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

void AsyncTCP_detail::tcp_error(void *arg, err_t err) {
  AsyncClient *c = reinterpret_cast<AsyncClient *>(arg);
  ASYNC_TCP_CONSOLE_E("%u Connection aborted or reset, err = %s", arg, c->errorToString(err));
  if (_is_client_slot_valid(c)) {
    _remove_events_for_client(c);
    c->_pcb = nullptr;
    c->_slot = INVALID_CLIENT_SLOT;
    _unregister_client_slot(c);

    // enqueue event to be processed in the async task for the user callback
    lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_ERROR, c};
    if (!e) {
      ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
      // Forcing error here may not be safe if calling is outside Async thread, but there's no other way.
      c->_error(err);
      return;
    }

    e->error.err = err;
    queue_mutex_guard guard;
    _send_async_event(e);
  }
}

void AsyncTCP_detail::_tcp_dns_found(const char *name, const ip_addr_t *ipaddr, void *arg) {
  ASYNC_TCP_CONSOLE_I("+DNS: name=%s ipaddr=0x%08x arg=%x\n", name, ipaddr, arg);
  AsyncClient *client = reinterpret_cast<AsyncClient *>(arg);

  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_DNS, client};
  if (!e) {
    ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
    return;
  }

  e->dns.name = name;
  if (ipaddr) {
    memcpy(&e->dns.addr, ipaddr, sizeof(ip_addr_t));
  } else {
    e->dns.addr.type = IPADDR_TYPE_ANY + 1;  // not IPv4 or IPv6 or IPv4+IPv6, @ref lwip_ip_addr_type
  }

  queue_mutex_guard guard;
  _send_async_event(e);
}

/*
 * TCP/IP API Calls
 * */

#include "lwip/priv/tcpip_priv.h"
typedef struct {
  struct tcpip_api_call_data call;
  AsyncClient *client;
  tcp_pcb *pcb;
  s8_t client_slot;
  err_t err;
  union {
    struct {
      const char *data;
      size_t size;
      uint8_t apiflags;
    } write;
    size_t received;
    struct {
      ip_addr_t *addr;
      tcp_connected_fn cb;
      void *arg;
      uint16_t port;
    } connect;
    struct {
      ip_addr_t *addr;
      const char *name;
      dns_found_callback cb;
      void *arg;
    } dns_found;
    struct {
      tcp_close_callback cb;
      void *arg;
    } close;
    struct {
      tcp_abort_callback cb;
      void *arg;
    } abort;
    struct {
      ip_addr_t *addr;
      u8_t type;
    } new_ip;
    struct {
      ip_addr_t *addr;
      uint16_t port;
    } bind;
    uint8_t backlog;
  };
} tcp_api_call_t;

static err_t _tcp_output_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (_is_pcb_slot_valid(msg->client_slot, msg->pcb)) {
    msg->err = tcp_output(msg->pcb);
  }
  return msg->err;
}

static esp_err_t _tcp_output(tcp_pcb *pcb, s8_t client_slot) {
  if (!pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.client_slot = client_slot;
  tcpip_api_call(_tcp_output_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_write_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_CONN;
  if (_is_pcb_slot_valid(msg->client_slot, msg->pcb)) {
    msg->err = tcp_write(msg->pcb, msg->write.data, msg->write.size, msg->write.apiflags);
  }
  return msg->err;
}

static esp_err_t _tcp_write(tcp_pcb *pcb, s8_t client_slot, const char *data, size_t size, uint8_t apiflags) {
  if (!pcb) {
    return ERR_CONN;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.client_slot = client_slot;
  msg.write.data = data;
  msg.write.size = size;
  msg.write.apiflags = apiflags;
  tcpip_api_call(_tcp_write_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_close_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_OK;
  if (_is_pcb_slot_valid(msg->client_slot, msg->pcb)) {
    _reset_tcp_callbacks(msg->pcb, nullptr);// It has to be called before tcp_close();
    msg->err = tcp_close(msg->pcb);
    if (msg->err != ERR_OK) {
      tcp_abort(msg->pcb);
      msg->err = ERR_ABRT;
    }
    if (msg->close.cb) {
      msg->close.cb(msg->close.arg);
    }
  }
  return msg->err;
}

static esp_err_t _tcp_close(tcp_pcb *pcb, s8_t client_slot, tcp_close_callback cb, void *arg) {
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.client_slot = client_slot;
  msg.close.cb = cb;
  msg.close.arg = arg;
  tcpip_api_call(_tcp_close_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_abort_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_OK;
  if (_is_pcb_slot_valid(msg->client_slot, msg->pcb)) {
    _reset_tcp_callbacks(msg->pcb, nullptr);// It has to be called before tcp_abort();
    tcp_abort(msg->pcb);
    msg->err = ERR_ABRT;
    if (msg->abort.cb) {
      msg->abort.cb(msg->abort.arg);
    }
  }
  return msg->err;
}

static esp_err_t _tcp_abort(tcp_pcb *pcb, s8_t client_slot, tcp_abort_callback cb, void *arg) {
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.client_slot = client_slot;
  msg.abort.cb = cb;
  msg.abort.arg = arg;
  tcpip_api_call(_tcp_close_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_connect_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  tcp_arg(msg->pcb, msg->connect.arg);
  msg->err = tcp_connect(msg->pcb, msg->connect.addr, msg->connect.port, msg->connect.cb);
  if (msg->err != ERR_OK) {
    ASYNC_TCP_CONSOLE_E("Error %d", msg->err);
    tcp_abort(msg->pcb);
    msg->err = ERR_ABRT;

  }
  return msg->err;
}

static esp_err_t _tcp_connect(tcp_pcb *pcb, s8_t client_slot, ip_addr_t *addr, uint16_t port, tcp_connected_fn cb, void *arg) {
  if (!pcb) {
    return ESP_FAIL;
  }
  tcp_api_call_t msg;
  msg.pcb = pcb;
  msg.connect.addr = addr;
  msg.connect.port = port;
  msg.connect.cb = cb;
  msg.connect.arg = arg;
  tcpip_api_call(_tcp_connect_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _dns_gethostbyname_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = dns_gethostbyname(msg->dns_found.name, msg->dns_found.addr, msg->dns_found.cb, msg->dns_found.arg);
  return msg->err;
}

static esp_err_t _dns_gethostbyname(const char *hostname, ip_addr_t *addr, dns_found_callback found, void *arg) {
  tcp_api_call_t msg;
  msg.dns_found.name = hostname;
  msg.dns_found.addr = addr;
  msg.dns_found.cb = found;
  msg.dns_found.arg = arg;
  tcpip_api_call(_dns_gethostbyname_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _tcp_new_ip_type_api(struct tcpip_api_call_data *api_call_msg) {
  tcp_api_call_t *msg = (tcp_api_call_t *)api_call_msg;
  msg->err = ERR_OK;
  msg->pcb = tcp_new_ip_type(msg->new_ip.type);
  return msg->err;
}

static tcp_pcb *_tcp_new_ip_type(u8_t type) {
  tcp_api_call_t msg;
  msg.new_ip.type = type;
  tcpip_api_call(_tcp_new_ip_type_api, (struct tcpip_api_call_data *)&msg);
  return msg.pcb;
}

/*
  Async TCP Client
 */

err_t asynctcp_callback(asynctcp_callback_fn function, void *ctx) {
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_CALLBACK, nullptr};
  if (!e) {
    ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
    return ERR_MEM;
  }
  e->callback.fn = function;
  e->callback.arg = ctx;

  queue_mutex_guard guard;
  _send_async_event(e);
  return ERR_OK;
}

AsyncClient::AsyncClient(tcp_pcb *pcb, AsyncServer *server)
  : _pcb(pcb), _server(server), _connect_cb(0), _connect_cb_arg(0), _discard_cb(0), _discard_cb_arg(0), _sent_cb(0), _sent_cb_arg(0), _error_cb(0),
    _error_cb_arg(0), _recv_cb(0), _recv_cb_arg(0), _pb_cb(0), _pb_cb_arg(0), _timeout_cb(0), _timeout_cb_arg(0), _poll_cb(0), _poll_cb_arg(0), _ack_pcb(true),
    _tx_last_packet(0), _rx_timeout(0), _rx_last_ack(0), _rx_ack_len(0), _ack_timeout(CONFIG_ASYNC_TCP_MAX_ACK_TIME), _connect_port(0), _slot(INVALID_CLIENT_SLOT) {
      ASYNC_TCP_CONSOLE_I("New client %u", this);
      if (_pcb) {
        _rx_last_packet = millis();
      }
    }

AsyncClient::~AsyncClient() {
  ASYNC_TCP_CONSOLE_I("Delete client %u", this);
  _server = nullptr;
  resetCallback();  // avoid any recursive callback
  if (_is_pcb_slot_valid(_slot, _pcb)) {
    _close(); // client is closed directly in lwIP thread
    _remove_events_for_client(this);
  }
}

/*
 * Operators
 * */

bool AsyncClient::operator==(const AsyncClient &other) const {
  return _pcb == other._pcb;
}

/*
 * Callback Setters
 * */

void AsyncClient::onConnect(AcConnectHandler cb, void *arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncClient::onDisconnect(AcConnectHandler cb, void *arg) {
  _discard_cb = cb;
  _discard_cb_arg = arg;
}

void AsyncClient::onAck(AcAckHandler cb, void *arg) {
  _sent_cb = cb;
  _sent_cb_arg = arg;
}

void AsyncClient::onError(AcErrorHandler cb, void *arg) {
  _error_cb = cb;
  _error_cb_arg = arg;
}

void AsyncClient::onData(AcDataHandler cb, void *arg) {
  _recv_cb = cb;
  _recv_cb_arg = arg;
}

void AsyncClient::onPacket(AcPacketHandler cb, void *arg) {
  _pb_cb = cb;
  _pb_cb_arg = arg;
}

void AsyncClient::onTimeout(AcTimeoutHandler cb, void *arg) {
  _timeout_cb = cb;
  _timeout_cb_arg = arg;
}

void AsyncClient::onPoll(AcConnectHandler cb, void *arg) {
  _poll_cb = cb;
  _poll_cb_arg = arg;
}

/*
 * Main Public Methods
 * */

bool AsyncClient::connect(ip_addr_t addr, uint16_t port) {
  if (_pcb) {
    ASYNC_TCP_CONSOLE_I("already connected, state %d", _pcb->state);
    return false;
  }
  if (!_start_async_task()) {
    ASYNC_TCP_CONSOLE_E("failed to start task");
    return false;
  }

  ASYNC_TCP_CONSOLE_I("Client %u Ip = %s port: %u", this, ipaddr_ntoa(&addr), port);

  if (_client_slot_available() == INVALID_CLIENT_SLOT) {
    ASYNC_TCP_CONSOLE_E("client slot full");
    return false;
  }
  
  tcp_pcb *pcb;
#if LWIP_IPV4 && LWIP_IPV6
  pcb = _tcp_new_ip_type(addr.type);
#else
  pcb = _tcp_new_ip_type(IPADDR_TYPE_V4);
#endif
  if (!pcb) {
    ASYNC_TCP_CONSOLE_E("pcb == NULL");
    return false;
  }

  esp_err_t err = _tcp_connect(pcb, _slot, &addr, port, AsyncTCP_detail::tcp_connected, this);
  bool result = (err == ESP_OK);
  if (!result) {
    ASYNC_TCP_CONSOLE_E("tcp_connect failed: %d", err);
  }
  return result;
}

#ifdef ARDUINO
bool AsyncClient::connect(const IPAddress &ip, uint16_t port) {
  ip_addr_t addr;
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  // if both IPv4 and IPv6 are enabled, ip_addr_t has a union field and the address type
  addr.u_addr.ip4.addr = ip;
  addr.type = IPADDR_TYPE_V4;
#else
  addr.addr = ip;
#endif
#else
  ip.to_ip_addr_t(&addr);
#endif
  ASYNC_TCP_CONSOLE_I("%u IP %s, port: %u", this, ip.toString().c_str(), port);
  return connect(addr, port);
}
#endif

#if LWIP_IPV6 && ESP_IDF_VERSION_MAJOR < 5
bool AsyncClient::connect(const IPv6Address &ip, uint16_t port) {
  auto ipaddr = static_cast<const uint32_t *>(ip);
  ip_addr_t addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);

  return connect(addr, port);
}
#endif

bool AsyncClient::connect(const char *host, uint16_t port) {
  ip_addr_t addr;

  ASYNC_TCP_CONSOLE_I("%u host %s, port: %u", this, host, port);

  if (!_start_async_task()) {
    ASYNC_TCP_CONSOLE_E("failed to start task");
    return false;
  }

  _connect_port = port;
  err_t err = _dns_gethostbyname(host, &addr, AsyncTCP_detail::_tcp_dns_found, this);

  if (err == ERR_OK) {
    ASYNC_TCP_CONSOLE_I("IP: %s\n", ipaddr_ntoa(&addr));
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV6
    if (addr.type == IPADDR_TYPE_V6) {
      return connect(IPv6Address(addr.u_addr.ip6.addr), port);
    }
    return connect(IPAddress(addr.u_addr.ip4.addr), port);
#else
    return connect(IPAddress(addr.addr), port);
#endif
#else
    return connect(addr, port);
#endif
  } else if (err == ERR_INPROGRESS) {
    ASYNC_TCP_CONSOLE_I("DNS query sent, waiting for callback...\n");
    return true;
  }
  ASYNC_TCP_CONSOLE_E("error: %d", err);
  return false;
}

/**
 * close() --> onDisconnect() --> ~AsyncClient()
*/
void AsyncClient::close(bool now) {
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_DISCONNECT, this};
  if (!e) {
    ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
    _close(); // client shall be closed directly in lwIP thread
    _remove_events_for_client(this);
    // Forcing disconnection here may not be safe if calling is outside Async thread, but there's no other way.
    _disconnect(ERR_CLSD);
    return;
  }

  if (now) {
    _close(); // client shall be closed directly in lwIP thread 
    _remove_events_for_client(this);
  } // else client shall be called to close in Async thread

  e->disconnect.err = now ? ERR_CLSD : ERR_ISCONN;
  queue_mutex_guard guard;
  if (now) {
    _prepend_async_event(e);
  } else {
    _send_async_event(e);
  }
}

/**
 * abort() -->onDisconnect() --> ~AsyncClient()
*/
err_t AsyncClient::abort() {
  _remove_events_for_client(this);
  lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_DISCONNECT, this};
  if (!e) {
    ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
    _abort(); // client shall be abort directly in lwIP thread
    // Forcing disconnection here may not be safe if calling is outside Async thread, but there's no other way.
    _disconnect(ERR_CLSD);
    return ERR_ABRT;
  }
  _abort(); // client shall be abort directly in lwIP thread
  e->disconnect.err = ERR_CLSD;
  queue_mutex_guard guard;
  _prepend_async_event(e);
  return ERR_ABRT;
}

size_t AsyncClient::space() const {
  if ((_pcb != NULL) && (_pcb->state == ESTABLISHED)) {
    return tcp_sndbuf(_pcb);
  }
  return 0;
}

size_t AsyncClient::add(const char *data, size_t size, uint8_t apiflags) {
  if (!_pcb || size == 0 || data == NULL) {
    return 0;
  }
  size_t room = space();
  if (!room) {
    return 0;
  }
  size_t will_send = (room < size) ? room : size;
  err_t err = ERR_OK;
  err = _tcp_write(_pcb, _slot, data, will_send, apiflags);
  if (err != ERR_OK) {
    return 0;
  }
  return will_send;
}

bool AsyncClient::send() {
  auto backup = _tx_last_packet;
  _tx_last_packet = millis();
  if (_tcp_output(_pcb, _slot) == ERR_OK) {
    return true;
  }
  _tx_last_packet = backup;
  return false;
}

size_t AsyncClient::ack(size_t len) {
  if (len > _rx_ack_len) {
    len = _rx_ack_len;
  }
  _rx_ack_len -= len;
  return len;
}

void AsyncClient::ackPacket(struct pbuf *pb) {
  if (!pb) {
    return;
  }
  pbuf_free(pb);
}

/*
 * Main Private Methods
 * */

err_t AsyncClient::_close() {
  ASYNC_TCP_CONSOLE_I("client %u", this);
  err_t err = ERR_OK;
#if (1)
  err = _tcp_close(_pcb, _slot, [](void *arg) {
    // run in LwIP thread
    AsyncClient *c = (AsyncClient *)arg;
    c->_pcb = nullptr;
    c->_slot = INVALID_CLIENT_SLOT;
    _unregister_client_slot(c);
  }, this);
#else
  tcpip_callback([](void *arg) {
    // run in LwIP thread
    AsyncClient *c = (AsyncClient *)arg;
    if (c->_pcb) {
      _reset_tcp_callbacks(c->_pcb, c); // It has to be called before tcp_close();
      if (tcp_close(c->_pcb) != ERR_OK) {
        tcp_abort(c->_pcb);
      }
    }
    c->_pcb = nullptr;
    c->_slot = INVALID_CLIENT_SLOT;
    _unregister_client_slot(c);
  }, this);
  delay(10); // Enable execution of the code on the LwIP thread via tcpip_callback (non-blocking)
#endif
  return err;
}

err_t AsyncClient::_abort() {
  ASYNC_TCP_CONSOLE_I("client %u", this);
#if (1)
  _tcp_abort(_pcb, _slot, [](void *arg) {
    // run in LwIP thread
    AsyncClient *c = (AsyncClient *)arg;
    c->_pcb = nullptr;
    c->_slot = INVALID_CLIENT_SLOT;
    _unregister_client_slot(c);
  }, this);
#else
  tcpip_callback([](void *arg) {
    // run in LwIP thread
    AsyncClient *c = (AsyncClient *)arg;
    if (c->_pcb) {
      _reset_tcp_callbacks(c->_pcb, c); // It has to be called before tcp_abort();
      tcp_abort(c->_pcb);
    }
    c->_pcb = nullptr;
    c->_slot = INVALID_CLIENT_SLOT;
    _unregister_client_slot(c);
  }, this);
  delay(10); // Enable execution of the code on the LwIP thread via tcpip_callback (non-blocking)
#endif
  return ERR_ABRT;
}

void AsyncClient::resetCallback() {
  _connect_cb = nullptr;
  _discard_cb = nullptr;
  _sent_cb = nullptr;
  _error_cb = nullptr;
  _recv_cb = nullptr;
  _pb_cb = nullptr;
  _timeout_cb = nullptr;
  _poll_cb = nullptr;
}

bool AsyncClient::valid() {
  return !!_pcb;
}

/*
 * Private Callbacks
 * */
err_t AsyncClient::_connected(tcp_pcb *pcb) {
  ASYNC_TCP_CONSOLE_I("client %u", this);
  if (_pcb) {
    _rx_last_packet = millis();
  }
  _tx_last_packet = 0;
  _rx_last_ack = 0;
  if (_connect_cb) {
    _connect_cb(_connect_cb_arg, this);
  }
  return ERR_OK;
}

void AsyncClient::_disconnect(err_t err) {
  ASYNC_TCP_CONSOLE_I("client %u", this);
  if (ERR_ISCONN == err) {
    _close(); // close client in lwIP thread 
  }

  if (_discard_cb) {
    _discard_cb(_discard_cb_arg, (_server) ? nullptr : this);
  }

  // Has to be called after callback _discard_cb()
  if (_server) {
    _server->_handleDisconnect(this);
  }
}

void AsyncClient::_error(err_t err) {
  ASYNC_TCP_CONSOLE_I("client %u", this);
  if (_error_cb) {
    _error_cb(_error_cb_arg, this, err);
  }
  _disconnect(ERR_CLSD);
}

// Must be called In LwIP Thread
err_t AsyncClient::_lwip_abort(tcp_pcb *pcb) {
  _remove_events_for_client(this);
  _reset_tcp_callbacks(pcb, this);
  tcp_abort(pcb);
  _pcb = nullptr;
  _slot = INVALID_CLIENT_SLOT;
  _unregister_client_slot(this);
  return ERR_ABRT;
}

// Must be called In LwIP Thread
err_t AsyncClient::_lwip_close(tcp_pcb *pcb) {
  err_t err = ERR_OK;
  _reset_tcp_callbacks(pcb, this);
  if (tcp_close(pcb) != ERR_OK) {
    tcp_abort(pcb);
    err = ERR_ABRT;
  }
  _pcb = nullptr;
  _slot = INVALID_CLIENT_SLOT;
  _unregister_client_slot(this);
  return err;
}

// In Async Thread
err_t AsyncClient::_fin(tcp_pcb *pcb, err_t err) {
  ASYNC_TCP_CONSOLE_I("client %u", this);
  _disconnect(ERR_CLSD);
  return ERR_OK;
}

err_t AsyncClient::_sent(tcp_pcb *pcb, uint16_t len) {
  _rx_last_ack = _rx_last_packet = millis();
  if (_sent_cb) {
    _sent_cb(_sent_cb_arg, this, len, (_rx_last_packet - _tx_last_packet));
  }
  return ERR_OK;
}

err_t AsyncClient::_recv(tcp_pcb *pcb, pbuf *pb, err_t err) {
  while (pb != NULL) {
    _rx_last_packet = millis();
    // we should not ack before we assimilate the data
    // _ack_pcb = true; // It is always true with whenever new client established. It should not force true here due to the ackLater() will not be valid anymore
    pbuf *b = pb;
    pb = b->next;
    b->next = NULL;
    if (_pb_cb) {
      _pb_cb(_pb_cb_arg, this, b);
    } else {
      if (_recv_cb) {
        _recv_cb(_recv_cb_arg, this, b->payload, b->len);
      }
      if (!_ack_pcb) {
        _rx_ack_len += b->len;
      }
      pbuf_free(b);
    }
  }
  return ERR_OK;
}

err_t AsyncClient::_poll(tcp_pcb *pcb) {
  if (!_pcb) {
    ASYNC_TCP_CONSOLE_E("pcb is NULL");
    return ERR_OK;
  }
  if (pcb != _pcb) {
    ASYNC_TCP_CONSOLE_E("0x%08" PRIx32 " != 0x%08" PRIx32, (uint32_t)pcb, (uint32_t)_pcb);
    return ERR_OK;
  }

  uint32_t now = millis();

  // ACK Timeout
  if (_ack_timeout) {
    const uint32_t one_day = 86400000;
    bool last_tx_is_after_last_ack = (_rx_last_ack - _tx_last_packet + one_day) < one_day;
    if (last_tx_is_after_last_ack && (now - _tx_last_packet) >= _ack_timeout) {
      ASYNC_TCP_CONSOLE_E("ack timeout %d", pcb->state);
      if (_timeout_cb) {
        _timeout_cb(_timeout_cb_arg, this, (now - _tx_last_packet));
      }
      return ERR_OK;
    }
  }
  // RX Timeout
  if (_rx_timeout && (now - _rx_last_packet) >= (_rx_timeout * 1000)) {
    ASYNC_TCP_CONSOLE_E("Client %u: rx timeout %d", this, pcb->state);
    _close(); // client shall be closed directly in lwIP thread
    _remove_events_for_client(this);
    _error(ERR_TIMEOUT);
    return ERR_OK;
  }
  // Everything is fine
  if (_poll_cb) {
    _poll_cb(_poll_cb_arg, this);
  }
  return ERR_OK;
}

void AsyncClient::_dns_found(ip_addr_t *ipaddr) {
  if (ipaddr->type == IPADDR_TYPE_ANY || ipaddr->type == IPADDR_TYPE_V4 || ipaddr->type == IPADDR_TYPE_V6) {
    ASYNC_TCP_CONSOLE_I("IP: %s\n", ipaddr_ntoa(ipaddr));
    connect(*ipaddr, _connect_port);
  } else {
    if (_error_cb) {
      _error_cb(_error_cb_arg, this, -55);
    }
    _disconnect(ERR_CLSD);
  }
}

/*
 * Public Helper Methods
 * */

bool AsyncClient::free() {
  if (!_pcb) {
    return true;
  }
  if (_pcb->state == CLOSED || _pcb->state > ESTABLISHED) {
    return true;
  }
  return false;
}

size_t AsyncClient::write(const char *data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);
  if (!will_send || !send()) {
    return 0;
  }
  return will_send;
}

void AsyncClient::setRxTimeout(uint32_t timeout) {
  _rx_timeout = timeout;
}

uint32_t AsyncClient::getRxTimeout() const {
  return _rx_timeout;
}

uint32_t AsyncClient::getAckTimeout() const {
  return _ack_timeout;
}

void AsyncClient::setAckTimeout(uint32_t timeout) {
  _ack_timeout = timeout;
}

void AsyncClient::setNoDelay(bool nodelay) const {
  if (!_pcb) {
    return;
  }
  if (nodelay) {
    tcp_nagle_disable(_pcb);
  } else {
    tcp_nagle_enable(_pcb);
  }
}

bool AsyncClient::getNoDelay() {
  if (!_pcb) {
    return false;
  }
  return tcp_nagle_disabled(_pcb);
}

void AsyncClient::setKeepAlive(uint32_t ms, uint8_t cnt) {
  if (ms != 0) {
    _pcb->so_options |= SOF_KEEPALIVE;  // Turn on TCP Keepalive for the given pcb
    // Set the time between keepalive messages in milli-seconds
    _pcb->keep_idle = ms;
    _pcb->keep_intvl = ms;
    _pcb->keep_cnt = cnt;  // The number of unanswered probes required to force closure of the socket
  } else {
    _pcb->so_options &= ~SOF_KEEPALIVE;  // Turn off TCP Keepalive for the given pcb
  }
}

uint16_t AsyncClient::getMss() const {
  if (!_pcb) {
    return 0;
  }
  return tcp_mss(_pcb);
}

uint32_t AsyncClient::getRemoteAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->remote_ip.u_addr.ip4.addr;
#else
  return _pcb->remote_ip.addr;
#endif
}

#if LWIP_IPV6
ip6_addr_t AsyncClient::getRemoteAddress6() const {
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V6) {
    return _pcb->remote_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip6_addr_t AsyncClient::getLocalAddress6() const {
  if (_pcb && _pcb->local_ip.type == IPADDR_TYPE_V6) {
    return _pcb->local_ip.u_addr.ip6;
  } else {
    ip6_addr_t nulladdr;
    ip6_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}
#ifdef ARDUINO
#if ESP_IDF_VERSION_MAJOR < 5
IPv6Address AsyncClient::remoteIP6() const {
  return IPv6Address(getRemoteAddress6().addr);
}

IPv6Address AsyncClient::localIP6() const {
  return IPv6Address(getLocalAddress6().addr);
}
#else
IPAddress AsyncClient::remoteIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
}

IPAddress AsyncClient::localIP6() const {
  if (!_pcb) {
    return IPAddress(IPType::IPv6);
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->local_ip));
  return ip;
}
#endif
#endif
#endif

uint16_t AsyncClient::getRemotePort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->remote_port;
}

uint32_t AsyncClient::getLocalAddress() const {
  if (!_pcb) {
    return 0;
  }
#if LWIP_IPV4 && LWIP_IPV6
  return _pcb->local_ip.u_addr.ip4.addr;
#else
  return _pcb->local_ip.addr;
#endif
}

uint16_t AsyncClient::getLocalPort() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->local_port;
}

ip4_addr_t AsyncClient::getRemoteAddress4() const {
#if LWIP_IPV4 && LWIP_IPV6
  if (_pcb && _pcb->remote_ip.type == IPADDR_TYPE_V4) {
    return _pcb->remote_ip.u_addr.ip4;
  }
#else
  if (_pcb) {
    return _pcb->remote_ip;
  }
#endif
  else {
    ip4_addr_t nulladdr;
    ip4_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

ip4_addr_t AsyncClient::getLocalAddress4() const {
#if LWIP_IPV4 && LWIP_IPV6
  if (_pcb && _pcb->local_ip.type == IPADDR_TYPE_V4) {
    return _pcb->local_ip.u_addr.ip4;
  }
#else
  if (_pcb) {
    return _pcb->local_ip;
  }
#endif
  else {
    ip4_addr_t nulladdr;
    ip4_addr_set_zero(&nulladdr);
    return nulladdr;
  }
}

#ifdef ARDUINO
IPAddress AsyncClient::remoteIP() const {
#if ESP_IDF_VERSION_MAJOR < 5
  return IPAddress(getRemoteAddress());
#else
  if (!_pcb) {
    return IPAddress();
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->remote_ip));
  return ip;
#endif
}

IPAddress AsyncClient::localIP() const {
#if ESP_IDF_VERSION_MAJOR < 5
  return IPAddress(getLocalAddress());
#else
  if (!_pcb) {
    return IPAddress();
  }
  IPAddress ip;
  ip.from_ip_addr_t(&(_pcb->local_ip));
  return ip;
#endif
}
#endif

uint8_t AsyncClient::state() const {
  if (!_pcb) {
    return 0;
  }
  return _pcb->state;
}

bool AsyncClient::connected() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state == ESTABLISHED;
}

bool AsyncClient::connecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > CLOSED && _pcb->state < ESTABLISHED;
}

bool AsyncClient::disconnecting() const {
  if (!_pcb) {
    return false;
  }
  return _pcb->state > ESTABLISHED && _pcb->state < TIME_WAIT;
}

bool AsyncClient::disconnected() const {
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state == TIME_WAIT;
}

bool AsyncClient::freeable() const {
  if (!_pcb) {
    return true;
  }
  return _pcb->state == CLOSED || _pcb->state > ESTABLISHED;
}

bool AsyncClient::canSend() const {
  return space() > 0;
}

const char *AsyncClient::errorToString(err_t error) {
  switch (error) {
    case ERR_OK:         return "OK";
    case ERR_MEM:        return "Out of memory error";
    case ERR_BUF:        return "Buffer error";
    case ERR_TIMEOUT:    return "Timeout";
    case ERR_RTE:        return "Routing problem";
    case ERR_INPROGRESS: return "Operation in progress";
    case ERR_VAL:        return "Illegal value";
    case ERR_WOULDBLOCK: return "Operation would block";
    case ERR_USE:        return "Address in use";
    case ERR_ALREADY:    return "Already connected";
    case ERR_CONN:       return "Not connected";
    case ERR_IF:         return "Low-level netif error";
    case ERR_ABRT:       return "Connection aborted";
    case ERR_RST:        return "Connection reset";
    case ERR_CLSD:       return "Connection closed";
    case ERR_ARG:        return "Illegal argument";
    case -55:            return "DNS failed";
    default:             return "UNKNOWN";
  }
}

const char *AsyncClient::stateToString() const {
  switch (state()) {
    case 0:  return "Closed";
    case 1:  return "Listen";
    case 2:  return "SYN Sent";
    case 3:  return "SYN Received";
    case 4:  return "Established";
    case 5:  return "FIN Wait 1";
    case 6:  return "FIN Wait 2";
    case 7:  return "Close Wait";
    case 8:  return "Closing";
    case 9:  return "Last ACK";
    case 10: return "Time Wait";
    default: return "UNKNOWN";
  }
}

/*
  Async TCP Server
 */

AsyncServer::AsyncServer(ip_addr_t addr, uint16_t port)
  : _port(port), _addr(addr), _noDelay(false), _listen_pcb(nullptr), _listen_connect_cb(nullptr), _connect_cb_arg(nullptr) {}

#ifdef ARDUINO
AsyncServer::AsyncServer(IPAddress addr, uint16_t port) : _port(port), _noDelay(false), _listen_pcb(nullptr), _listen_connect_cb(nullptr), _connect_cb_arg(nullptr) {
#if ESP_IDF_VERSION_MAJOR < 5
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_V4;
  _addr.u_addr.ip4.addr = addr;
#else
  _addr.addr = addr;
#endif
#else
  addr.to_ip_addr_t(&_addr);
#endif
}
#if ESP_IDF_VERSION_MAJOR < 5 && __has_include(<IPv6Address.h>) && LWIP_IPV6
AsyncServer::AsyncServer(IPv6Address addr, uint16_t port) : _port(port), _noDelay(false), _listen_pcb(nullptr), _listen_connect_cb(nullptr), _connect_cb_arg(nullptr) {
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_V6;
#endif
  auto ipaddr = static_cast<const uint32_t *>(addr);
  _addr = IPADDR6_INIT(ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
}
#endif
#endif

AsyncServer::AsyncServer(uint16_t port) : _port(port), _noDelay(false), _listen_pcb(nullptr), _listen_connect_cb(nullptr), _connect_cb_arg(nullptr) {
#if LWIP_IPV4 && LWIP_IPV6
  _addr.type = IPADDR_TYPE_ANY;
  _addr.u_addr.ip4.addr = INADDR_ANY;
#else
  _addr.addr = INADDR_ANY;
#endif
}

AsyncServer::~AsyncServer() {
  end();
}

void AsyncServer::onClient(AcConnectHandler cb, void *arg) {
  _listen_connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncServer::begin() {
  if (_listen_pcb) {
    return;
  }

  if (!_start_async_task()) {
    ASYNC_TCP_CONSOLE_E("failed to start task");
    return;
  }

  // Safely to run in the LwIP thread
  tcpip_callback([](void *arg) {
    AsyncServer *server = (AsyncServer *)arg;
    err_t err;
#if LWIP_IPV4 && LWIP_IPV6
    server->_listen_pcb = tcp_new_ip_type(server->_addr.type);
#else
    _pcb = _tcp_new_ip_type(IPADDR_TYPE_ANY);
#endif
    if (!server->_listen_pcb) {
      ASYNC_TCP_CONSOLE_E("_pcb == NULL");
      return;
    }

    err = tcp_bind(server->_listen_pcb, &server->_addr, server->_port);

    if (err != ERR_OK) {
      ASYNC_TCP_CONSOLE_E("bind error: %d", err);
      tcp_abort(server->_listen_pcb); // forcibly free unbound PCB
      server->_listen_pcb = NULL;
      return;
    }

    constexpr uint8_t backlog = CONFIG_LWIP_MAX_ACTIVE_TCP / 2; // up to you
    server->_listen_pcb = tcp_listen_with_backlog(server->_listen_pcb, backlog);
    if (!server->_listen_pcb) {
      ASYNC_TCP_CONSOLE_E("listen_pcb == NULL");
      return;
    }
    tcp_arg(server->_listen_pcb, (void *)server);
    tcp_accept(server->_listen_pcb, &AsyncTCP_detail::tcp_accept);
  }, this);
}

void AsyncServer::end() {
  tcpip_callback([](void *arg) {
    // run in LwIP thread
    AsyncServer *s = (AsyncServer *)arg;
    if (s->_listen_pcb) {
      tcp_arg(s->_listen_pcb, NULL);
      tcp_accept(s->_listen_pcb, NULL);
      if (tcp_close(s->_listen_pcb) != ERR_OK) {
        tcp_abort(s->_listen_pcb);
      }
      s->_listen_pcb = NULL;
    }

#if (0)
    for (int i = 0; i < CONFIG_LWIP_MAX_ACTIVE_TCP; ++i) {
    AsyncClient *c = _clients[i];
    if (c && c->_pcb && (c->_server == s)) {
      c->_lwip_close(c->_pcb); // close immediately in LwIP thread
      lwip_tcp_event_packet_t *e = new (std::nothrow) lwip_tcp_event_packet_t{LWIP_TCP_FIN, c};
      if (!e) {
        ASYNC_TCP_CONSOLE_E("Failed to allocate event packet");
        c->_error(ERR_MEM);
        continue;
      }
      e->sent.pcb = c->_pcb;
      e->recv.err = ERR_OK;

      queue_mutex_guard guard;
      _send_async_event(e);
    }
  }
#endif
  }, this);

#if (1)
  for (int i = 0; i < CONFIG_LWIP_MAX_ACTIVE_TCP; ++i) {
    AsyncClient *c = _clients[i];
    if (c && c->_pcb && c->_server == this) {
      c->close(true);  // close immediately in LwIP thread
    }
  }
#endif

  delay(10); // Enable execution of the code on the LwIP thread via tcpip_callback (non-blocking)
}

err_t AsyncServer::_accepted(AsyncClient *client) {
  if (_listen_connect_cb) {
    _listen_connect_cb(_connect_cb_arg, client);
  }
  return ERR_OK;
}

void AsyncServer::_handleDisconnect(AsyncClient *client) {
  if (client) {
    delete client;
  }
}

void AsyncServer::setNoDelay(bool nodelay) {
  _noDelay = nodelay;
}

bool AsyncServer::getNoDelay() const {
  return _noDelay;
}

uint8_t AsyncServer::status() const {
  if (!_listen_pcb) {
    return 0;
  }
  return _listen_pcb->state;
}
