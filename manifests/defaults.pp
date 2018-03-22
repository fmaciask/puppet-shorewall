# ex: si ts=4 sw=4 et

class shorewall::defaults (
  $blacklist_filename  = 'blrules',
  $header_lead         = '',
  $mangle_filename     = 'mangle',
  $service_restart     = 'restart',
  $service6_restart    = 'restart',
) {
}
