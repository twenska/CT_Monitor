# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: proto/tls_options.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import descriptor_pb2 as google_dot_protobuf_dot_descriptor__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='proto/tls_options.proto',
  package='ctpy',
  syntax='proto2',
  serialized_options=None,
  serialized_pb=_b('\n\x17proto/tls_options.proto\x12\x04\x63tpy\x1a google/protobuf/descriptor.proto\"\xe1\x01\n\nTLSOptions\x12\x14\n\x0c\x62ytes_in_use\x18\x01 \x01(\r\x12\x11\n\tmax_value\x18\x02 \x01(\r\x12\x14\n\x0c\x66ixed_length\x18\x03 \x01(\r\x12\x12\n\nmin_length\x18\x04 \x01(\r\x12\x12\n\nmax_length\x18\x05 \x01(\r\x12\x18\n\x10min_total_length\x18\x06 \x01(\r\x12\x18\n\x10max_total_length\x18\x07 \x01(\r\x12\x14\n\x0cselect_field\x18\x08 \x01(\t\x12\x14\n\x0cselect_value\x18\t \x01(\r\x12\x0c\n\x04skip\x18\n \x01(\x08:B\n\x08tls_opts\x12\x1d.google.protobuf.FieldOptions\x18\xff\x07 \x01(\x0b\x32\x10.ctpy.TLSOptions:F\n\rtls_enum_opts\x12\x1c.google.protobuf.EnumOptions\x18\xff\x07 \x01(\x0b\x32\x10.ctpy.TLSOptions')
  ,
  dependencies=[google_dot_protobuf_dot_descriptor__pb2.DESCRIPTOR,])


TLS_OPTS_FIELD_NUMBER = 1023
tls_opts = _descriptor.FieldDescriptor(
  name='tls_opts', full_name='ctpy.tls_opts', index=0,
  number=1023, type=11, cpp_type=10, label=1,
  has_default_value=False, default_value=None,
  message_type=None, enum_type=None, containing_type=None,
  is_extension=True, extension_scope=None,
  serialized_options=None, file=DESCRIPTOR)
TLS_ENUM_OPTS_FIELD_NUMBER = 1023
tls_enum_opts = _descriptor.FieldDescriptor(
  name='tls_enum_opts', full_name='ctpy.tls_enum_opts', index=1,
  number=1023, type=11, cpp_type=10, label=1,
  has_default_value=False, default_value=None,
  message_type=None, enum_type=None, containing_type=None,
  is_extension=True, extension_scope=None,
  serialized_options=None, file=DESCRIPTOR)


_TLSOPTIONS = _descriptor.Descriptor(
  name='TLSOptions',
  full_name='ctpy.TLSOptions',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='bytes_in_use', full_name='ctpy.TLSOptions.bytes_in_use', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='max_value', full_name='ctpy.TLSOptions.max_value', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='fixed_length', full_name='ctpy.TLSOptions.fixed_length', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='min_length', full_name='ctpy.TLSOptions.min_length', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='max_length', full_name='ctpy.TLSOptions.max_length', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='min_total_length', full_name='ctpy.TLSOptions.min_total_length', index=5,
      number=6, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='max_total_length', full_name='ctpy.TLSOptions.max_total_length', index=6,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='select_field', full_name='ctpy.TLSOptions.select_field', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='select_value', full_name='ctpy.TLSOptions.select_value', index=8,
      number=9, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='skip', full_name='ctpy.TLSOptions.skip', index=9,
      number=10, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=68,
  serialized_end=293,
)

DESCRIPTOR.message_types_by_name['TLSOptions'] = _TLSOPTIONS
DESCRIPTOR.extensions_by_name['tls_opts'] = tls_opts
DESCRIPTOR.extensions_by_name['tls_enum_opts'] = tls_enum_opts
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

TLSOptions = _reflection.GeneratedProtocolMessageType('TLSOptions', (_message.Message,), {
  'DESCRIPTOR' : _TLSOPTIONS,
  '__module__' : 'proto.tls_options_pb2'
  # @@protoc_insertion_point(class_scope:ctpy.TLSOptions)
  })
_sym_db.RegisterMessage(TLSOptions)

tls_opts.message_type = _TLSOPTIONS
google_dot_protobuf_dot_descriptor__pb2.FieldOptions.RegisterExtension(tls_opts)
tls_enum_opts.message_type = _TLSOPTIONS
google_dot_protobuf_dot_descriptor__pb2.EnumOptions.RegisterExtension(tls_enum_opts)

# @@protoc_insertion_point(module_scope)
