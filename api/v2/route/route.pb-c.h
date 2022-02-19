/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: api/route/route.proto */

#ifndef PROTOBUF_C_api_2froute_2froute_2eproto__INCLUDED
#define PROTOBUF_C_api_2froute_2froute_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003002 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "route/route_components.pb-c.h"
#include "core/base.pb-c.h"

typedef struct _Route__RouteConfiguration Route__RouteConfiguration;


/* --- enums --- */


/* --- messages --- */

struct  _Route__RouteConfiguration
{
  ProtobufCMessage base;
  Core__ApiStatus api_status;
  char *name;
  size_t n_virtual_hosts;
  Route__VirtualHost **virtual_hosts;
};
#define ROUTE__ROUTE_CONFIGURATION__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&route__route_configuration__descriptor) \
    , CORE__API_STATUS__NONE, (char *)protobuf_c_empty_string, 0,NULL }


/* Route__RouteConfiguration methods */
void   route__route_configuration__init
                     (Route__RouteConfiguration         *message);
size_t route__route_configuration__get_packed_size
                     (const Route__RouteConfiguration   *message);
size_t route__route_configuration__pack
                     (const Route__RouteConfiguration   *message,
                      uint8_t             *out);
size_t route__route_configuration__pack_to_buffer
                     (const Route__RouteConfiguration   *message,
                      ProtobufCBuffer     *buffer);
Route__RouteConfiguration *
       route__route_configuration__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   route__route_configuration__free_unpacked
                     (Route__RouteConfiguration *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Route__RouteConfiguration_Closure)
                 (const Route__RouteConfiguration *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor route__route_configuration__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_api_2froute_2froute_2eproto__INCLUDED */
